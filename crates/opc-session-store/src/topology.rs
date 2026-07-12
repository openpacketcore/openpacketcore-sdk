//! Validated identity and membership for replicated session stores.
//!
//! Topology admission is deliberately separate from backend capabilities and
//! runtime readiness. It proves that configured votes are distinct and that
//! exactly one member is the local replica; it does not prove reachability,
//! authenticated peer identity, durable commit authority, or repair safety.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::capability::SessionStorePlatformProfile;
use crate::quorum::{FencedSessionReplica, SessionStoreBackend};

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

/// Field of a configured authenticated-backend binding rejected by topology.
///
/// Values are deliberately categorical so errors never disclose identities,
/// descriptor fingerprints, endpoints, or cluster/configuration scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendPeerBindingField {
    /// The adapter was configured from a different local logical member.
    LocalReplicaId,
    /// The adapter targets a different remote logical member.
    RemoteReplicaId,
    /// The adapter expects a different remote TLS identity.
    RemoteTlsIdentity,
    /// The adapter was configured from a different local descriptor.
    LocalDescriptorFingerprint,
    /// The adapter was configured from a different remote descriptor.
    RemoteDescriptorFingerprint,
    /// The adapter used a different configured voting-set size.
    ConfiguredMemberCount,
    /// Peer adapters do not share one cluster/configuration scope.
    Scope,
}

impl fmt::Display for BackendPeerBindingField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LocalReplicaId => "local-replica-id",
            Self::RemoteReplicaId => "remote-replica-id",
            Self::RemoteTlsIdentity => "remote-tls-identity",
            Self::LocalDescriptorFingerprint => "local-descriptor-fingerprint",
            Self::RemoteDescriptorFingerprint => "remote-descriptor-fingerprint",
            Self::ConfiguredMemberCount => "configured-member-count",
            Self::Scope => "scope",
        })
    }
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
    /// A backend did not provide the stable process-local identity required
    /// for duplicate-allocation admission checks.
    #[error("configured member backend does not provide an instance identity")]
    MissingBackendInstanceIdentity,
    /// Two member records expose the same process-local adapter identity.
    #[error("configured members contain a duplicate backend instance")]
    DuplicateBackendInstance,
    /// One network-bound topology omitted composition evidence for a remote
    /// member.
    #[error("configured remote member is missing an authenticated backend peer binding")]
    MissingBackendPeerBinding,
    /// One configured adapter binding disagreed with immutable topology.
    #[error("configured backend peer binding does not match topology field {field}")]
    BackendPeerBindingMismatch {
        /// Stable redaction-safe mismatch category.
        field: BackendPeerBindingField,
    },
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

    pub(crate) fn unvalidated_legacy(index: usize) -> Self {
        let backing = format!("legacy-backing-{index}");
        Self {
            replica_id: ReplicaId(format!("legacy-{index}")),
            endpoint: ReplicaEndpoint {
                host: format!("legacy-{index}.invalid"),
                port: 1,
            },
            tls_identity: ReplicaTlsIdentity(format!("legacy-tls-{index}")),
            failure_domain: ReplicaFailureDomain(format!("legacy-failure-domain-{index}")),
            backing_identity: ReplicaBackingIdentity(Sha256::digest(backing.as_bytes()).into()),
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

/// A declared member paired with the backend adapter used to reach it.
#[derive(Clone)]
pub struct QuorumReplicaMember {
    descriptor: QuorumReplicaDescriptor,
    replica: FencedSessionReplica,
}

impl QuorumReplicaMember {
    /// Pair immutable topology metadata with a backend replica wrapper.
    pub fn new(descriptor: QuorumReplicaDescriptor, replica: FencedSessionReplica) -> Self {
        Self {
            descriptor,
            replica,
        }
    }

    /// Declared immutable identity of this member.
    pub fn descriptor(&self) -> &QuorumReplicaDescriptor {
        &self.descriptor
    }

    /// Backend and fault-injection wrapper for this member.
    pub fn replica(&self) -> &FencedSessionReplica {
        &self.replica
    }

    /// Replace the backend adapter while retaining topology and fault controls.
    #[must_use]
    pub fn with_backend(mut self, backend: Arc<dyn SessionStoreBackend>) -> Self {
        self.replica.inner = backend;
        self
    }
}

/// Unvalidated requested HA topology.
#[derive(Clone)]
pub struct QuorumTopologyConfig {
    local_replica_id: ReplicaId,
    members: Vec<QuorumReplicaMember>,
}

impl QuorumTopologyConfig {
    /// Define an HA membership set and its exact local logical replica ID.
    pub fn new(local_replica_id: ReplicaId, members: Vec<QuorumReplicaMember>) -> Self {
        Self {
            local_replica_id,
            members,
        }
    }
}

/// Admission mode of a constructed session topology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum QuorumTopologyMode {
    /// Odd membership of 3 through [`QUORUM_TOPOLOGY_MAX_MEMBERS`] validated
    /// distinct replicas.
    ValidatedHa,
    /// Explicit one-member lab profile; never an HA claim.
    LabSingleton,
    /// Deprecated raw-vector construction with no identity evidence.
    UnvalidatedLegacy,
}

impl QuorumTopologyMode {
    /// Stable diagnostic code for this topology mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidatedHa => "validated-ha",
            Self::LabSingleton => "lab-singleton",
            Self::UnvalidatedLegacy => "unvalidated-legacy",
        }
    }

    /// Platform capability this topology is allowed to advertise.
    pub const fn platform_profile(self) -> SessionStorePlatformProfile {
        match self {
            Self::ValidatedHa => SessionStorePlatformProfile::Quorum,
            Self::LabSingleton => SessionStorePlatformProfile::SingleReplica,
            Self::UnvalidatedLegacy => SessionStorePlatformProfile::Unknown,
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

    /// Exact local logical ID, absent only for deprecated raw construction.
    pub fn local_replica_id(&self) -> Option<&ReplicaId> {
        self.local_replica_id.as_ref()
    }

    pub(crate) fn unvalidated_legacy(configured_members: usize) -> Self {
        Self {
            mode: QuorumTopologyMode::UnvalidatedLegacy,
            configured_members,
            required_quorum: 0,
            local_replica_id: None,
        }
    }
}

/// Immutable topology that passed HA or explicit singleton admission.
#[derive(Clone)]
pub struct ValidatedQuorumTopology {
    summary: QuorumTopologySummary,
    members: Vec<QuorumReplicaMember>,
}

impl ValidatedQuorumTopology {
    /// Validate an explicit one-member lab topology.
    ///
    /// This profile is operational for tests and labs but advertises
    /// [`SessionStorePlatformProfile::SingleReplica`], never quorum HA.
    pub fn try_new_lab_singleton(
        local_replica_id: ReplicaId,
        members: Vec<QuorumReplicaMember>,
    ) -> Result<Self, QuorumTopologyError> {
        validate_topology(local_replica_id, members, QuorumTopologyMode::LabSingleton)
    }

    /// Redaction-safe admitted shape.
    pub fn summary(&self) -> &QuorumTopologySummary {
        &self.summary
    }

    /// Platform profile this admitted topology is permitted to advertise.
    pub const fn platform_profile(&self) -> SessionStorePlatformProfile {
        self.summary.mode.platform_profile()
    }

    /// Validated configured members.
    pub fn members(&self) -> &[QuorumReplicaMember] {
        &self.members
    }

    /// Map backend adapters without discarding or mutating topology identity.
    ///
    /// The mapped topology is revalidated, so a wrapper that omits the backend
    /// identity contract or aliases an existing physical instance fails closed.
    /// Callers must also preserve each member's canonical backing identity;
    /// authenticated backend binding remains a separate requirement.
    pub fn try_map_backends<F>(self, mut map: F) -> Result<Self, QuorumTopologyError>
    where
        F: FnMut(
            &QuorumReplicaDescriptor,
            Arc<dyn SessionStoreBackend>,
        ) -> Arc<dyn SessionStoreBackend>,
    {
        let mode = self.summary.mode;
        let local_replica_id = self
            .summary
            .local_replica_id
            .clone()
            .ok_or(QuorumTopologyError::MissingLocalReplica)?;
        let members = self
            .members
            .into_iter()
            .map(|member| {
                let backend = map(&member.descriptor, member.replica.inner.clone());
                member.with_backend(backend)
            })
            .collect();
        validate_topology(local_replica_id, members, mode)
    }

    pub(crate) fn into_parts(self) -> (QuorumTopologySummary, Vec<QuorumReplicaMember>) {
        (self.summary, self.members)
    }
}

impl TryFrom<QuorumTopologyConfig> for ValidatedQuorumTopology {
    type Error = QuorumTopologyError;

    fn try_from(config: QuorumTopologyConfig) -> Result<Self, Self::Error> {
        validate_topology(
            config.local_replica_id,
            config.members,
            QuorumTopologyMode::ValidatedHa,
        )
    }
}

fn validate_topology(
    local_replica_id: ReplicaId,
    members: Vec<QuorumReplicaMember>,
    mode: QuorumTopologyMode,
) -> Result<ValidatedQuorumTopology, QuorumTopologyError> {
    if members.len() > QUORUM_TOPOLOGY_MAX_MEMBERS {
        return Err(QuorumTopologyError::MemberCountTooLarge {
            configured: members.len(),
            max: QUORUM_TOPOLOGY_MAX_MEMBERS,
        });
    }

    match mode {
        QuorumTopologyMode::ValidatedHa if members.len() < 3 => {
            return Err(QuorumTopologyError::HaMemberCountTooSmall {
                configured: members.len(),
            });
        }
        QuorumTopologyMode::ValidatedHa if members.len().is_multiple_of(2) => {
            return Err(QuorumTopologyError::HaMemberCountMustBeOdd {
                configured: members.len(),
            });
        }
        QuorumTopologyMode::LabSingleton if members.len() != 1 => {
            return Err(QuorumTopologyError::LabMemberCount {
                configured: members.len(),
            });
        }
        QuorumTopologyMode::UnvalidatedLegacy => {
            return Err(QuorumTopologyError::MissingLocalReplica);
        }
        _ => {}
    }

    let self_matches = members
        .iter()
        .filter(|member| member.descriptor.replica_id == local_replica_id)
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
    let mut backend_instances = Vec::with_capacity(members.len());

    for member in &members {
        let descriptor = &member.descriptor;
        if !replica_ids.insert(descriptor.replica_id.clone()) {
            return Err(QuorumTopologyError::DuplicateReplicaId);
        }
        if !endpoints.insert(descriptor.endpoint.clone()) {
            return Err(QuorumTopologyError::DuplicateEndpoint);
        }
        if !tls_identities.insert(descriptor.tls_identity.clone()) {
            return Err(QuorumTopologyError::DuplicateTlsIdentity);
        }
        if !failure_domains.insert(descriptor.failure_domain.clone()) {
            return Err(QuorumTopologyError::DuplicateFailureDomain);
        }
        if !backing_identities.insert(descriptor.backing_identity.clone()) {
            return Err(QuorumTopologyError::DuplicateBackingIdentity);
        }
        let backend_instance = member
            .replica
            .inner
            .backend_instance_identity()
            .ok_or(QuorumTopologyError::MissingBackendInstanceIdentity)?;
        if backend_instances.contains(&backend_instance) {
            return Err(QuorumTopologyError::DuplicateBackendInstance);
        }
        backend_instances.push(backend_instance);
    }

    let configured_members = members.len();
    let local_descriptor_fingerprint = members
        .iter()
        .find(|member| member.descriptor.replica_id == local_replica_id)
        .map(|member| member.descriptor.configuration_fingerprint())
        .ok_or(QuorumTopologyError::MissingLocalReplica)?;
    let peer_bindings = members
        .iter()
        .map(|member| member.replica.inner.peer_binding())
        .collect::<Vec<_>>();

    if peer_bindings.iter().any(Option::is_some) {
        let mut shared_scope = None;
        for (member, binding) in members.iter().zip(&peer_bindings) {
            let Some(binding) = binding else {
                if member.descriptor.replica_id == local_replica_id {
                    // An in-process local backend does not traverse an
                    // authenticated peer connection and may remain unbound.
                    continue;
                }
                return Err(QuorumTopologyError::MissingBackendPeerBinding);
            };

            if binding.local_replica_id() != &local_replica_id {
                return Err(QuorumTopologyError::BackendPeerBindingMismatch {
                    field: BackendPeerBindingField::LocalReplicaId,
                });
            }
            if binding.local_descriptor_fingerprint() != &local_descriptor_fingerprint {
                return Err(QuorumTopologyError::BackendPeerBindingMismatch {
                    field: BackendPeerBindingField::LocalDescriptorFingerprint,
                });
            }
            if binding.remote_replica_id() != member.descriptor.replica_id() {
                return Err(QuorumTopologyError::BackendPeerBindingMismatch {
                    field: BackendPeerBindingField::RemoteReplicaId,
                });
            }
            if binding.remote_tls_identity() != member.descriptor.tls_identity() {
                return Err(QuorumTopologyError::BackendPeerBindingMismatch {
                    field: BackendPeerBindingField::RemoteTlsIdentity,
                });
            }
            if binding.remote_descriptor_fingerprint()
                != &member.descriptor.configuration_fingerprint()
            {
                return Err(QuorumTopologyError::BackendPeerBindingMismatch {
                    field: BackendPeerBindingField::RemoteDescriptorFingerprint,
                });
            }
            if usize::from(binding.configured_member_count()) != configured_members {
                return Err(QuorumTopologyError::BackendPeerBindingMismatch {
                    field: BackendPeerBindingField::ConfiguredMemberCount,
                });
            }

            if let Some(expected_scope) = shared_scope {
                if binding.scope() != &expected_scope {
                    return Err(QuorumTopologyError::BackendPeerBindingMismatch {
                        field: BackendPeerBindingField::Scope,
                    });
                }
            } else {
                shared_scope = Some(*binding.scope());
            }
        }
    }

    let required_quorum = (configured_members / 2) + 1;
    Ok(ValidatedQuorumTopology {
        summary: QuorumTopologySummary {
            mode,
            configured_members,
            required_quorum,
            local_replica_id: Some(local_replica_id),
        },
        members,
    })
}
