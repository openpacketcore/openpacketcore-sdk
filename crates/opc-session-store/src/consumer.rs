//! Least-authority application consumer contract for a session quorum.
//!
//! This module intentionally models only application state and lease
//! operations. It has no Openraft member, vote, topology, snapshot, or raw
//! replication-rebuild operation. A transport authenticates a
//! [`SessionConsumerIdentity`] separately from quorum members, then forwards
//! the typed request to a quorum-side implementation of
//! [`SessionQuorumConsumer`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    AtomicFencedTransitionCapability, BackendCapabilities, CompareAndSet, CompareAndSetResult,
    FencedTransitionObservation, FencedTransitionOutcome, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionStatus, LeaseError, LeaseGuard, OwnerId,
    QuorumReplicaDescriptor, RecordExpiryPreflight, RestoreScanPage, RestoreScanRequest,
    SessionConsensusIdentity, SessionConsensusNodeId, SessionConsensusRequestId, SessionKey,
    SessionOp, SessionOpResult, StoreError, StoredSessionRecord,
    FENCED_TRANSITION_REQUEST_ID_BYTES, QUORUM_TOPOLOGY_MAX_MEMBERS,
};

#[cfg(test)]
use crate::MAX_REPLICATION_OPERATIONS_PER_ENTRY;

/// Maximum batch slots admitted by one consumer request.
pub const MAX_SESSION_CONSUMER_BATCH_OPERATIONS: usize = 256;

/// Maximum serialized batch response bytes retained for one consumer request.
///
/// This is deliberately lower than the transport frame ceiling. It bounds the
/// aggregate of otherwise individually valid point-read results before the
/// quorum service retains them in a batch response.
pub const MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum projected watch bytes queued for one authenticated consumer.
///
/// The consumer registry applies this bound before it clones a change to a
/// subscriber, so a large raw replication entry cannot multiply by consumer
/// connections in the backend's watch queues.
pub const MAX_SESSION_CONSUMER_WATCH_BUFFER_BYTES: usize = 256 * 1024;

/// Fixed byte width of one durable consumer request identity.
pub const SESSION_CONSUMER_REQUEST_ID_BYTES: usize = 16;

/// Maximum UTF-8 width of an authenticated consumer identity.
pub const SESSION_CONSUMER_IDENTITY_MAX_BYTES: usize = 253;

/// Maximum distinct authenticated application consumers in one manifest.
pub const MAX_SESSION_CONSUMER_AUTHORIZATION_IDENTITIES: usize = 256;
/// Maximum tenant/NF grants retained for one authenticated consumer.
pub const MAX_SESSION_CONSUMER_AUTHORIZATION_SCOPES_PER_IDENTITY: usize = 256;
/// Maximum total identity-to-tenant/NF grant tuples in one manifest.
pub const MAX_SESSION_CONSUMER_AUTHORIZATION_GRANT_TUPLES: usize = 4096;

const SESSION_CONSUMER_ROSTER_IDENTITY_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/session-consumer-roster/identity/v1\0";
const SESSION_CONSUMER_ROSTER_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/session-consumer-roster/commitment/v1\0";
const SESSION_CONSUMER_TENANT_NF_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/session-consumer-tenant-nf-scope/v1\0";

/// Redaction-safe construction failure for [`SessionConsumerIdentity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid session consumer identity")]
pub struct SessionConsumerIdentityError;

/// Authenticated application identity, deliberately distinct from a quorum
/// member/node identity.
///
/// This value is supplied by the mTLS authorization layer, never by a
/// consumer request frame. Its textual form is retained only for identity
/// binding of durable request IDs and is redacted from `Debug` and errors.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionConsumerIdentity(String);

impl SessionConsumerIdentity {
    /// Validate one canonical authenticated application identity.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionConsumerIdentityError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > SESSION_CONSUMER_IDENTITY_MAX_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(SessionConsumerIdentityError);
        }
        Ok(Self(value))
    }

    /// Borrow the identity for authenticated authorization and request binding.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SessionConsumerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerIdentity(<redacted>)")
    }
}

/// Fixed-width client-generated request identity for one consumer operation.
///
/// The quorum-side adapter combines it with the authenticated consumer
/// identity before submitting the existing durable consensus request ID. A
/// client may explicitly retry an unconfirmed request with this same ID, but
/// this SDK never performs that replay automatically.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionConsumerRequestId([u8; SESSION_CONSUMER_REQUEST_ID_BYTES]);

impl SessionConsumerRequestId {
    /// Generate a new opaque request identity.
    pub fn new() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Reconstruct an identity retained by an application across a retry.
    pub const fn from_bytes(bytes: [u8; SESSION_CONSUMER_REQUEST_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width representation.
    pub const fn as_bytes(&self) -> &[u8; SESSION_CONSUMER_REQUEST_ID_BYTES] {
        &self.0
    }
}

impl Default for SessionConsumerRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SessionConsumerRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRequestId(<redacted>)")
    }
}

/// Exact cluster/configuration/epoch scope a consumer must present on every
/// request.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsumerScope(SessionConsensusIdentity);

impl SessionConsumerScope {
    /// Bind the consumer contract to one exact consensus scope.
    pub const fn new(identity: SessionConsensusIdentity) -> Self {
        Self(identity)
    }

    /// Return the exact consensus identity being scoped.
    pub const fn consensus_identity(self) -> SessionConsensusIdentity {
        self.0
    }
}

impl fmt::Debug for SessionConsumerScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerScope(<redacted>)")
    }
}

/// Fixed-width, domain-separated commitment to one admitted consumer roster.
///
/// The constructor remains internal to the store-issued authorization
/// manifest. Its bytes are safe to retain or compare, but `Debug` deliberately
/// omits them so topology material cannot enter diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionConsumerRosterCommitment([u8; 32]);

impl SessionConsumerRosterCommitment {
    /// Borrow the fixed-width commitment for equality checks or durable local
    /// binding. This is a digest, never a raw topology value.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SessionConsumerRosterCommitment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterCommitment(<redacted>)")
    }
}

/// One store-issued, node-keyed member of an admitted consumer roster.
///
/// The exact TLS/SPIFFE identity is retained solely so the existing consumer
/// listener can exclude every voting identity. The paired roster commitment
/// binds its domain-separated identity commitment to this non-zero node ID.
/// There is intentionally no public constructor.
#[derive(Clone)]
pub struct SessionConsumerRosterMember {
    node_id: SessionConsensusNodeId,
    tls_identity: SessionConsumerIdentity,
    identity_commitment: [u8; 32],
}

impl SessionConsumerRosterMember {
    /// Canonical non-zero consensus node ID assigned to this member.
    pub const fn node_id(&self) -> SessionConsensusNodeId {
        self.node_id
    }

    /// Exact admitted TLS/SPIFFE identity for this consensus node.
    ///
    /// This is exposed only through a store-issued manifest so a consumer
    /// listener can continue to reject quorum-member credentials.
    pub fn tls_identity(&self) -> &str {
        self.tls_identity.as_str()
    }
}

impl fmt::Debug for SessionConsumerRosterMember {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRosterMember(<redacted>)")
    }
}

/// Redaction-safe failure while converting exact topology descriptor bindings
/// into a consumer roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid session consumer roster")]
pub enum SessionConsumerRosterError {
    /// The topology has no consensus identity from which to bind a roster.
    MissingConsensusIdentity,
    /// The exact voter set was empty.
    Empty,
    /// The exact voter set exceeded the SDK's bounded maximum.
    MemberCountTooLarge,
    /// More than one descriptor named the same consensus node ID.
    DuplicateNodeId,
    /// More than one descriptor named the same TLS/SPIFFE identity.
    DuplicateTlsIdentity,
    /// A supplied or expected consensus node ID was invalid.
    InvalidNodeId,
    /// A supplied TLS/SPIFFE identity was invalid for the consumer boundary.
    InvalidTlsIdentity,
    /// Descriptors did not exactly cover the authoritative voter set.
    ScopeMismatch,
}

/// Scope-bound canonical consensus-voter roster.
///
/// The public value can be obtained only from validated SDK topology or from a
/// store-issued authorization manifest. Its private fields prevent product
/// code from inventing a node mapping or roster commitment.
#[derive(Clone)]
pub struct SessionConsumerRoster {
    scope: SessionConsumerScope,
    consensus_members: BTreeMap<SessionConsensusNodeId, SessionConsumerRosterMember>,
    roster_commitment: SessionConsumerRosterCommitment,
}

impl SessionConsumerRoster {
    /// Construct one roster from the store's exact current voter IDs and
    /// descriptors. `expected_members` is the current scope's authoritative
    /// voter set; every supplied descriptor must correspond to it exactly.
    ///
    /// Raw node IDs are accepted only at this crate-private boundary so the
    /// conversion rejects zero and non-portable ordinals before a roster member
    /// can exist. The public roster always carries `SessionConsensusNodeId`.
    pub(crate) fn try_new(
        scope: SessionConsumerScope,
        expected_members: &BTreeSet<SessionConsensusNodeId>,
        descriptors: impl IntoIterator<Item = (u64, QuorumReplicaDescriptor)>,
    ) -> Result<Self, SessionConsumerRosterError> {
        validate_expected_roster_members(expected_members)?;

        let mut consensus_members = BTreeMap::new();
        let mut tls_identities = BTreeSet::new();
        for (raw_node_id, descriptor) in descriptors {
            let node_id = SessionConsensusNodeId::new(raw_node_id)
                .map_err(|_| SessionConsumerRosterError::InvalidNodeId)?;
            if consensus_members.contains_key(&node_id) {
                return Err(SessionConsumerRosterError::DuplicateNodeId);
            }
            if !expected_members.contains(&node_id) {
                return Err(SessionConsumerRosterError::ScopeMismatch);
            }
            let tls_identity = SessionConsumerIdentity::new(descriptor.tls_identity().as_str())
                .map_err(|_| SessionConsumerRosterError::InvalidTlsIdentity)?;
            if !tls_identities.insert(tls_identity.clone()) {
                return Err(SessionConsumerRosterError::DuplicateTlsIdentity);
            }
            let identity_commitment = roster_identity_commitment(&tls_identity);
            consensus_members.insert(
                node_id,
                SessionConsumerRosterMember {
                    node_id,
                    tls_identity,
                    identity_commitment,
                },
            );
        }

        if consensus_members.len() != expected_members.len() {
            return Err(SessionConsumerRosterError::ScopeMismatch);
        }

        let roster_commitment = SessionConsumerRosterCommitment(roster_commitment(
            scope.consensus_identity(),
            &consensus_members,
        ));
        Ok(Self {
            scope,
            consensus_members,
            roster_commitment,
        })
    }

    /// Exact scope attested by the quorum store when this manifest was made.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Fixed-width commitment to this exact scope and sorted node-to-identity
    /// roster. Reordering the source descriptor map cannot change it.
    pub const fn roster_commitment(&self) -> SessionConsumerRosterCommitment {
        self.roster_commitment
    }

    /// Iterate the authoritative node-to-TLS/SPIFFE roster in ascending
    /// canonical node-ID order without exposing a constructor that could
    /// replace it.
    pub fn consensus_members(&self) -> impl Iterator<Item = &SessionConsumerRosterMember> {
        self.consensus_members.values()
    }

    /// Iterate the authoritative member exclusion set without exposing a
    /// constructor that could replace it.
    pub fn consensus_member_identities(&self) -> impl Iterator<Item = &str> {
        self.consensus_members
            .values()
            .map(SessionConsumerRosterMember::tls_identity)
    }

    /// Number of exact voters bound by this roster.
    pub fn voter_count(&self) -> usize {
        self.consensus_members.len()
    }

    /// Derive private-field authority for one exact roster member.
    pub fn voter(&self, node_id: SessionConsensusNodeId) -> Option<SessionConsumerVoterAuthority> {
        self.consensus_members
            .get(&node_id)
            .cloned()
            .map(|member| SessionConsumerVoterAuthority {
                scope: self.scope,
                member,
                voter_count: self.consensus_members.len(),
                roster_commitment: self.roster_commitment,
            })
    }

    /// Bind explicit application grants to this already SDK-validated roster.
    ///
    /// This is the safe composition path for an SDK client that obtained this
    /// roster from [`crate::ValidatedQuorumTopology`]. It cannot create or
    /// alter the roster, its scope, or its voter-to-TLS identity bindings.
    pub fn authorization_manifest(
        self,
        local_node_id: SessionConsensusNodeId,
        grants: impl IntoIterator<Item = SessionConsumerAuthorizationGrant>,
    ) -> Result<SessionConsumerAuthorizationManifest, SessionConsumerAuthorizationManifestError>
    {
        SessionConsumerAuthorizationManifest::try_new(local_node_id, self, grants)
    }
}

impl fmt::Debug for SessionConsumerRoster {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerRoster")
            .field("scope", &self.scope)
            .field("consensus_member_count", &self.consensus_members.len())
            .field("roster_commitment", &self.roster_commitment)
            .finish()
    }
}

/// Private-field authority for one exact server in a canonical roster.
///
/// Callers can inspect the fixed binding needed to configure transport, but
/// cannot construct or substitute one from raw node or commitment bytes.
#[derive(Clone)]
pub struct SessionConsumerVoterAuthority {
    scope: SessionConsumerScope,
    member: SessionConsumerRosterMember,
    voter_count: usize,
    roster_commitment: SessionConsumerRosterCommitment,
}

impl SessionConsumerVoterAuthority {
    /// Exact consensus scope shared by the voter roster.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Exact SDK consensus node ID expected from this server.
    pub const fn node_id(&self) -> SessionConsensusNodeId {
        self.member.node_id
    }

    /// Exact configured TLS/SPIFFE identity for this server.
    pub fn tls_identity(&self) -> &str {
        self.member.tls_identity.as_str()
    }

    /// Exact voter count committed by the roster.
    pub const fn voter_count(&self) -> usize {
        self.voter_count
    }

    /// Exact canonical roster commitment expected from this server.
    pub const fn roster_commitment(&self) -> SessionConsumerRosterCommitment {
        self.roster_commitment
    }
}

impl fmt::Debug for SessionConsumerVoterAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerVoterAuthority(<redacted>)")
    }
}

/// Exact tenant and network-function namespace granted to one consumer.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionConsumerTenantNfScope {
    tenant: TenantId,
    nf_kind: NetworkFunctionKind,
}

impl SessionConsumerTenantNfScope {
    /// Construct one explicit tenant/NF scope. Neither field is inferred from
    /// SPIFFE, Kubernetes, a session key, or another deployment identity.
    pub const fn new(tenant: TenantId, nf_kind: NetworkFunctionKind) -> Self {
        Self { tenant, nf_kind }
    }

    /// Exact tenant named by this grant.
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Exact network-function kind named by this grant.
    pub const fn nf_kind(&self) -> &NetworkFunctionKind {
        &self.nf_kind
    }
}

impl fmt::Debug for SessionConsumerTenantNfScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerTenantNfScope(<redacted>)")
    }
}

/// Invalid bounded grant construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerAuthorizationGrantError {
    /// The exact SPIFFE identity was not valid for this consumer boundary.
    #[error("invalid session consumer authorization grant identity")]
    InvalidIdentity,
    /// A grant must name at least one exact tenant/NF scope.
    #[error("session consumer authorization grant has no scopes")]
    EmptyScopes,
    /// A grant exceeded the bounded scopes-per-identity limit.
    #[error("session consumer authorization grant has too many scopes")]
    TooManyScopes,
    /// The input named one exact tenant/NF scope more than once.
    #[error("session consumer authorization grant contains a duplicate scope")]
    DuplicateScope,
}

/// Explicit SPIFFE-to-tenant/NF authorization grant.
///
/// The identity is parsed before construction and every grant contains a
/// nonempty, bounded, duplicate-free scope set. Wildcards are not supported.
#[derive(Clone)]
pub struct SessionConsumerAuthorizationGrant {
    consumer: SessionConsumerIdentity,
    scopes: BTreeSet<SessionConsumerTenantNfScope>,
}

impl SessionConsumerAuthorizationGrant {
    /// Construct one explicit bounded authorization grant.
    pub fn try_new(
        consumer: SpiffeId,
        scopes: impl IntoIterator<Item = SessionConsumerTenantNfScope>,
    ) -> Result<Self, SessionConsumerAuthorizationGrantError> {
        let mut admitted_scopes = BTreeSet::new();
        for scope in scopes {
            if !admitted_scopes.insert(scope) {
                return Err(SessionConsumerAuthorizationGrantError::DuplicateScope);
            }
            if admitted_scopes.len() > MAX_SESSION_CONSUMER_AUTHORIZATION_SCOPES_PER_IDENTITY {
                return Err(SessionConsumerAuthorizationGrantError::TooManyScopes);
            }
        }
        if admitted_scopes.is_empty() {
            return Err(SessionConsumerAuthorizationGrantError::EmptyScopes);
        }
        let consumer = SessionConsumerIdentity::new(consumer.as_str().to_owned())
            .map_err(|_| SessionConsumerAuthorizationGrantError::InvalidIdentity)?;
        Ok(Self {
            consumer,
            scopes: admitted_scopes,
        })
    }
}

impl fmt::Debug for SessionConsumerAuthorizationGrant {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerAuthorizationGrant(<redacted>)")
    }
}

/// Invalid store-issued consumer authorization manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionConsumerAuthorizationManifestError {
    /// The manifest local voter was not present in its exact roster.
    #[error("session consumer authorization local voter is absent from the roster")]
    LocalVoterMissing,
    /// An application grant attempted to reuse a consensus voter identity.
    #[error("session consumer authorization grant reuses a voter identity")]
    VoterIdentity,
    /// More than one grant named the same exact SPIFFE identity.
    #[error("session consumer authorization manifest contains a duplicate identity")]
    DuplicateIdentity,
    /// The manifest exceeded its bounded identity limit.
    #[error("session consumer authorization manifest has too many identities")]
    TooManyIdentities,
    /// The manifest exceeded its bounded total grant tuple limit.
    #[error("session consumer authorization manifest has too many grant tuples")]
    TooManyGrantTuples,
    /// The manifest must contain at least one application consumer grant.
    #[error("session consumer authorization manifest has no consumers")]
    Empty,
}

/// Non-constructible authenticated consumer authority passed to the quorum
/// service after mTLS authorization.
#[derive(Clone)]
pub struct SessionConsumerAuthorization {
    identity: SessionConsumerIdentity,
    allowed_scopes: Arc<BTreeSet<[u8; 32]>>,
}

impl fmt::Debug for SessionConsumerAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerAuthorization(<redacted>)")
    }
}

/// Store-issued local-voter manifest containing one canonical roster and a
/// bounded explicit authorization map. It is never serialized.
#[derive(Clone)]
pub struct SessionConsumerAuthorizationManifest {
    local_node_id: SessionConsensusNodeId,
    roster: SessionConsumerRoster,
    consumers: BTreeMap<SessionConsumerIdentity, Arc<BTreeSet<[u8; 32]>>>,
}

impl SessionConsumerAuthorizationManifest {
    pub(crate) fn try_new(
        local_node_id: SessionConsensusNodeId,
        roster: SessionConsumerRoster,
        grants: impl IntoIterator<Item = SessionConsumerAuthorizationGrant>,
    ) -> Result<Self, SessionConsumerAuthorizationManifestError> {
        if roster.voter(local_node_id).is_none() {
            return Err(SessionConsumerAuthorizationManifestError::LocalVoterMissing);
        }
        let member_identities = roster
            .consensus_member_identities()
            .collect::<BTreeSet<_>>();
        let mut consumers = BTreeMap::new();
        let mut total_scopes = 0_usize;
        for grant in grants {
            if member_identities.contains(grant.consumer.as_str()) {
                return Err(SessionConsumerAuthorizationManifestError::VoterIdentity);
            }
            if consumers.contains_key(&grant.consumer) {
                return Err(SessionConsumerAuthorizationManifestError::DuplicateIdentity);
            }
            total_scopes = total_scopes
                .checked_add(grant.scopes.len())
                .ok_or(SessionConsumerAuthorizationManifestError::TooManyGrantTuples)?;
            if consumers.len() >= MAX_SESSION_CONSUMER_AUTHORIZATION_IDENTITIES {
                return Err(SessionConsumerAuthorizationManifestError::TooManyIdentities);
            }
            if total_scopes > MAX_SESSION_CONSUMER_AUTHORIZATION_GRANT_TUPLES {
                return Err(SessionConsumerAuthorizationManifestError::TooManyGrantTuples);
            }
            let allowed_scopes = grant
                .scopes
                .iter()
                .map(session_consumer_tenant_nf_commitment)
                .collect::<BTreeSet<_>>();
            consumers.insert(grant.consumer, Arc::new(allowed_scopes));
        }
        if consumers.is_empty() {
            return Err(SessionConsumerAuthorizationManifestError::Empty);
        }
        Ok(Self {
            local_node_id,
            roster,
            consumers,
        })
    }

    /// Exact consensus scope authorized by this manifest.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.roster.scope
    }

    /// Exact local server node ID bound by this manifest.
    pub const fn local_node_id(&self) -> SessionConsensusNodeId {
        self.local_node_id
    }

    /// Exact voter count bound by this manifest.
    pub fn voter_count(&self) -> usize {
        self.roster.voter_count()
    }

    /// Exact canonical roster commitment bound by this manifest.
    pub const fn roster_commitment(&self) -> SessionConsumerRosterCommitment {
        self.roster.roster_commitment
    }

    /// Iterate the exact consensus-member exclusion identities.
    pub fn consensus_member_identities(&self) -> impl Iterator<Item = &str> {
        self.roster.consensus_member_identities()
    }

    /// Iterate the exact canonical voter roster bound to this manifest.
    pub fn consensus_members(&self) -> impl Iterator<Item = &SessionConsumerRosterMember> {
        self.roster.consensus_members()
    }

    /// Resolve one already-authenticated configured consumer into a
    /// non-constructible quorum-service authority token.
    pub fn authorize(
        &self,
        identity: &SessionConsumerIdentity,
    ) -> Result<SessionConsumerAuthorization, SessionConsumerRejection> {
        let allowed_scopes = self
            .consumers
            .get(identity)
            .cloned()
            .ok_or(SessionConsumerRejection::Unauthorized)?;
        Ok(SessionConsumerAuthorization {
            identity: identity.clone(),
            allowed_scopes,
        })
    }
}

impl fmt::Debug for SessionConsumerAuthorizationManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerAuthorizationManifest")
            .field("local_node_id", &"<redacted>")
            .field("voter_count", &self.roster.voter_count())
            .field("consumer_count", &self.consumers.len())
            .finish()
    }
}

fn session_consumer_tenant_nf_commitment(scope: &SessionConsumerTenantNfScope) -> [u8; 32] {
    session_consumer_tenant_nf_fields_commitment(scope.tenant.as_str(), scope.nf_kind.as_str())
}

fn session_consumer_tenant_nf_fields_commitment(tenant: &str, nf_kind: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_CONSUMER_TENANT_NF_COMMITMENT_DOMAIN);
    update_length_delimited(&mut hasher, tenant.as_bytes());
    update_length_delimited(&mut hasher, nf_kind.as_bytes());
    hasher.finalize().into()
}

fn validate_expected_roster_members(
    expected_members: &BTreeSet<SessionConsensusNodeId>,
) -> Result<(), SessionConsumerRosterError> {
    if expected_members.is_empty() {
        return Err(SessionConsumerRosterError::Empty);
    }
    if expected_members.len() > QUORUM_TOPOLOGY_MAX_MEMBERS {
        return Err(SessionConsumerRosterError::MemberCountTooLarge);
    }
    if expected_members
        .iter()
        .any(|node_id| node_id.get() == 0 || node_id.get() > i64::MAX as u64)
    {
        return Err(SessionConsumerRosterError::InvalidNodeId);
    }
    Ok(())
}

fn roster_identity_commitment(identity: &SessionConsumerIdentity) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_CONSUMER_ROSTER_IDENTITY_COMMITMENT_DOMAIN);
    update_length_delimited(&mut hasher, identity.as_str().as_bytes());
    hasher.finalize().into()
}

fn roster_commitment(
    scope: SessionConsensusIdentity,
    consensus_members: &BTreeMap<SessionConsensusNodeId, SessionConsumerRosterMember>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_CONSUMER_ROSTER_COMMITMENT_DOMAIN);
    update_length_delimited(&mut hasher, scope.cluster_id().as_bytes());
    update_length_delimited(&mut hasher, scope.configuration_id().as_bytes());
    update_length_delimited(
        &mut hasher,
        &scope.configuration_epoch().get().to_be_bytes(),
    );
    hasher.update(
        u32::try_from(consensus_members.len())
            .expect("consumer roster member count is bounded")
            .to_be_bytes(),
    );
    for (node_id, member) in consensus_members {
        hasher.update(node_id.get().to_be_bytes());
        update_length_delimited(&mut hasher, &member.identity_commitment);
    }
    hasher.finalize().into()
}

fn update_length_delimited(hasher: &mut Sha256, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("consumer roster field length is bounded");
    hasher.update(length.to_be_bytes());
    hasher.update(value);
}

/// Typed operation admitted by the stateless consumer boundary.
///
/// Deliberately absent are consensus-engine RPCs, membership/topology changes,
/// snapshots, raw replication append, and replication rebuild.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SessionConsumerOperation {
    /// Read the quorum's current backend capability declaration.
    Capabilities,
    /// Authoritative, linearizable record read.
    Get {
        /// Session key to retrieve.
        key: SessionKey,
    },
    /// Validate payload-free absolute-expiry preflights at leader authority.
    PreflightRecordExpiry {
        /// Bounded payload-free expiry descriptors.
        preflights: Vec<RecordExpiryPreflight>,
    },
    /// Fenced compare-and-set mutation.
    CompareAndSet {
        /// Exact fenced mutation.
        op: Box<CompareAndSet>,
    },
    /// Fenced deletion.
    DeleteFenced {
        /// Existing lease credential.
        lease: LeaseGuard,
    },
    /// Fenced TTL refresh.
    RefreshTtl {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Bounded sequential application batch.
    Batch {
        /// Operations in caller order.
        ops: Vec<SessionOp>,
    },
    /// Bounded restore scan.
    ScanRestoreRecords {
        /// Requested restore page.
        request: RestoreScanRequest,
    },
    /// Open a bounded committed-change watch from the inclusive sequence.
    Watch {
        /// Inclusive committed sequence to watch.
        start_sequence: u64,
    },
    /// Acquire a fenced lease.
    AcquireLease {
        /// Session key to lease.
        key: SessionKey,
        /// Requested owner.
        owner: OwnerId,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Renew an existing lease.
    RenewLease {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Recover the exact durable receipt for one ordinary lease mutation.
    ///
    /// This is a leader-linearizable, read-only operation.  The complete
    /// original public request identity and lease body are retained by the
    /// caller and rebuilt by the server under its authenticated identity; it
    /// never accepts a derived consensus ID or submits a lease mutation.
    LeaseMutationStatus {
        /// Complete original lease request retained by the caller.
        request: Box<SessionConsumerLeaseMutationRequest>,
    },
    /// Recover the exact durable outcome of one compare-and-set.
    ///
    /// This is a leader-linearizable, read-only operation. The complete
    /// original request is retained by the caller's local affine handle;
    /// it is never replayed or proposed by this status operation.
    CompareAndSetStatus {
        /// Complete original compare-and-set request retained by the caller.
        request: Box<SessionConsumerCompareAndSetRequest>,
    },
    /// Prove the exact atomic fenced-transition capability across the current
    /// admitted voter set.
    FencedTransitionCapability,
    /// Observe one exact record key and its durable fence floor.
    ObserveFencedTransition {
        /// Exact key to observe.
        key: SessionKey,
    },
    /// Atomically acquire or renew one lease and mutate its exact record.
    FencedTransition {
        /// Complete canonical transition body.
        request: Box<FencedTransitionRequest>,
    },
    /// Recover the exact status of one previously submitted transition.
    FencedTransitionStatus {
        /// Complete canonical transition body.
        request: Box<FencedTransitionRequest>,
    },
    /// Release an existing lease.
    ReleaseLease {
        /// Existing lease credential.
        lease: LeaseGuard,
    },
}

impl fmt::Debug for SessionConsumerOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Capabilities => "Capabilities",
            Self::Get { .. } => "Get",
            Self::PreflightRecordExpiry { .. } => "PreflightRecordExpiry",
            Self::CompareAndSet { .. } => "CompareAndSet",
            Self::DeleteFenced { .. } => "DeleteFenced",
            Self::RefreshTtl { .. } => "RefreshTtl",
            Self::Batch { .. } => "Batch",
            Self::ScanRestoreRecords { .. } => "ScanRestoreRecords",
            Self::Watch { .. } => "Watch",
            Self::AcquireLease { .. } => "AcquireLease",
            Self::RenewLease { .. } => "RenewLease",
            Self::LeaseMutationStatus { .. } => "LeaseMutationStatus",
            Self::CompareAndSetStatus { .. } => "CompareAndSetStatus",
            Self::ReleaseLease { .. } => "ReleaseLease",
            Self::FencedTransitionCapability => "FencedTransitionCapability",
            Self::ObserveFencedTransition { .. } => "ObserveFencedTransition",
            Self::FencedTransition { .. } => "FencedTransition",
            Self::FencedTransitionStatus { .. } => "FencedTransitionStatus",
        };
        formatter.write_str(name)
    }
}

impl SessionConsumerOperation {
    /// Check fixed consumer-side operation bounds before quorum dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        let validate_lease = |lease: &LeaseGuard| {
            lease
                .validate_profile()
                .map_err(|_| SessionConsumerRejection::MalformedRequest)
        };
        match self {
            Self::PreflightRecordExpiry { preflights } => {
                crate::validate_record_expiry_preflights_profile(preflights)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::Batch { ops } => {
                if ops.len() > MAX_SESSION_CONSUMER_BATCH_OPERATIONS {
                    return Err(SessionConsumerRejection::MalformedRequest);
                }
                crate::validate_session_ops_profile(ops)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::ScanRestoreRecords { request } => request
                .validate()
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::CompareAndSet { op } => validate_lease(&op.lease),
            Self::DeleteFenced { lease } | Self::ReleaseLease { lease } => validate_lease(lease),
            Self::RefreshTtl { lease, ttl } | Self::RenewLease { lease, ttl } => {
                validate_lease(lease)?;
                crate::validate_session_ttl(*ttl)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::AcquireLease { ttl, .. } => crate::validate_session_ttl(*ttl)
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::LeaseMutationStatus { request } => request.validate(),
            Self::CompareAndSetStatus { request } => request.validate(),
            Self::FencedTransition { request } | Self::FencedTransitionStatus { request } => {
                request
                    .validate()
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::Capabilities
            | Self::Get { .. }
            | Self::Watch { .. }
            | Self::FencedTransitionCapability
            | Self::ObserveFencedTransition { .. } => Ok(()),
        }
    }
}

/// One scope-bound consumer request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerRequest {
    scope: SessionConsumerScope,
    request_id: SessionConsumerRequestId,
    operation: SessionConsumerOperation,
}

impl SessionConsumerRequest {
    /// Construct one exact operation request.
    pub const fn new(
        scope: SessionConsumerScope,
        request_id: SessionConsumerRequestId,
        operation: SessionConsumerOperation,
    ) -> Self {
        Self {
            scope,
            request_id,
            operation,
        }
    }

    /// Exact cluster/configuration/epoch scope supplied by the caller.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Caller-retained durable request identity.
    pub const fn request_id(&self) -> SessionConsumerRequestId {
        self.request_id
    }

    /// Typed application operation.
    pub const fn operation(&self) -> &SessionConsumerOperation {
        &self.operation
    }

    /// Consume the request after server-side validation and binding have
    /// completed. This is crate-private so the consensus service can move one
    /// maximum-sized CAS body directly into its single commit intent without
    /// cloning it for validation or receipt bookkeeping.
    pub(crate) fn into_operation(self) -> SessionConsumerOperation {
        self.operation
    }

    /// Validate the operation before dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation.validate()?;
        match &self.operation {
            SessionConsumerOperation::FencedTransition { request }
            | SessionConsumerOperation::FencedTransitionStatus { request }
                if request.request_id().as_bytes() != self.request_id.as_bytes() =>
            {
                Err(SessionConsumerRejection::MalformedRequest)
            }
            SessionConsumerOperation::LeaseMutationStatus { request }
                if request.request_id().as_bytes() != self.request_id.as_bytes() =>
            {
                Err(SessionConsumerRejection::MalformedRequest)
            }
            SessionConsumerOperation::CompareAndSetStatus { request }
                if request.request_id().as_bytes() != self.request_id.as_bytes() =>
            {
                Err(SessionConsumerRejection::MalformedRequest)
            }
            _ => Ok(()),
        }
    }
}

/// Complete original compare-and-set request used only for read-only exact
/// consensus-outcome recovery.
///
/// The public request ID and immutable body are retained by the volatile
/// local affine handle. This type has no execute operation and cannot mint a new
/// request identity or replay the mutation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerCompareAndSetRequest {
    request_id: SessionConsumerRequestId,
    operation: CompareAndSet,
}

impl SessionConsumerCompareAndSetRequest {
    /// Construct one retained compare-and-set body from its caller-owned ID.
    pub const fn new(request_id: SessionConsumerRequestId, operation: CompareAndSet) -> Self {
        Self {
            request_id,
            operation,
        }
    }

    /// Return the original caller-owned public request identity.
    pub const fn request_id(&self) -> SessionConsumerRequestId {
        self.request_id
    }

    /// Return the exact original compare-and-set body.
    pub const fn operation(&self) -> &CompareAndSet {
        &self.operation
    }

    /// Validate the retained body before it reaches the receipt lookup.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation
            .lease
            .validate_profile()
            .map_err(|_| SessionConsumerRejection::MalformedRequest)
    }

    pub(crate) fn into_original_consumer_request(
        self,
        scope: SessionConsumerScope,
    ) -> SessionConsumerRequest {
        let operation = SessionConsumerOperation::CompareAndSet {
            op: Box::new(self.operation),
        };
        SessionConsumerRequest::new(scope, self.request_id, operation)
    }
}

impl fmt::Debug for SessionConsumerCompareAndSetRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerCompareAndSetRequest(<redacted>)")
    }
}

/// One ordinary lease operation whose complete original body is retained for
/// exact receipt recovery.
///
/// This type deliberately contains the public request ID and original body,
/// rather than an internal consensus request ID or digest.  The server derives
/// every internal binding from the authenticated consumer identity and exact
/// consumer scope at the read boundary.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "lease_operation",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerLeaseMutationOperation {
    /// Original acquire-lease body.
    Acquire {
        /// Session key to lease.
        key: SessionKey,
        /// Requested owner.
        owner: OwnerId,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Original renew-lease body.
    Renew {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Original release-lease body.
    Release {
        /// Existing lease credential.
        lease: LeaseGuard,
    },
}

impl fmt::Debug for SessionConsumerLeaseMutationOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Acquire { .. } => "Acquire",
            Self::Renew { .. } => "Renew",
            Self::Release { .. } => "Release",
        };
        formatter.write_str(name)
    }
}

impl SessionConsumerLeaseMutationOperation {
    fn validate(&self) -> Result<(), SessionConsumerRejection> {
        let validate_lease = |lease: &LeaseGuard| {
            lease
                .validate_profile()
                .map_err(|_| SessionConsumerRejection::MalformedRequest)
        };
        match self {
            Self::Acquire { ttl, .. } => crate::validate_session_ttl(*ttl)
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::Renew { lease, ttl } => {
                validate_lease(lease)?;
                crate::validate_session_ttl(*ttl)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::Release { lease } => validate_lease(lease),
        }
    }

    fn into_consumer_operation(self) -> SessionConsumerOperation {
        match self {
            Self::Acquire { key, owner, ttl } => {
                SessionConsumerOperation::AcquireLease { key, owner, ttl }
            }
            Self::Renew { lease, ttl } => SessionConsumerOperation::RenewLease { lease, ttl },
            Self::Release { lease } => SessionConsumerOperation::ReleaseLease { lease },
        }
    }
}

/// Complete original public lease request used only for read-only receipt
/// recovery.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerLeaseMutationRequest {
    request_id: SessionConsumerRequestId,
    operation: SessionConsumerLeaseMutationOperation,
}

impl SessionConsumerLeaseMutationRequest {
    /// Construct a retained ordinary lease request from its original public
    /// request ID and complete mutation body.
    pub const fn new(
        request_id: SessionConsumerRequestId,
        operation: SessionConsumerLeaseMutationOperation,
    ) -> Self {
        Self {
            request_id,
            operation,
        }
    }

    /// Return the original caller-owned public request identity.
    pub const fn request_id(&self) -> SessionConsumerRequestId {
        self.request_id
    }

    /// Return the exact original lease body.
    pub const fn operation(&self) -> &SessionConsumerLeaseMutationOperation {
        &self.operation
    }

    /// Validate the retained body before it reaches the receipt lookup.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation.validate()
    }

    pub(crate) fn into_original_consumer_request(
        self,
        scope: SessionConsumerScope,
    ) -> SessionConsumerRequest {
        let operation = self.operation.into_consumer_operation();
        SessionConsumerRequest::new(scope, self.request_id, operation)
    }
}

impl fmt::Debug for SessionConsumerLeaseMutationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerLeaseMutationRequest(<redacted>)")
    }
}

impl SessionConsumerAuthorization {
    pub(crate) fn identity(&self) -> &SessionConsumerIdentity {
        &self.identity
    }

    fn permits_key(&self, key: &SessionKey) -> bool {
        let commitment =
            session_consumer_tenant_nf_fields_commitment(key.tenant.as_str(), key.nf_kind.as_str());
        self.allowed_scopes.contains(&commitment)
    }

    fn permits_compare_and_set(&self, operation: &CompareAndSet) -> bool {
        self.permits_key(&operation.key)
            && self.permits_key(operation.lease.key())
            && self.permits_key(&operation.new_record.key)
    }

    fn permits_session_op(&self, operation: &SessionOp) -> bool {
        match operation {
            SessionOp::Get { key } => self.permits_key(key),
            SessionOp::CompareAndSet(operation) => self.permits_compare_and_set(operation),
            SessionOp::DeleteFenced { lease } | SessionOp::RefreshTtl { lease, .. } => {
                self.permits_key(lease.key())
            }
        }
    }

    fn permits_lease_mutation(&self, request: &SessionConsumerLeaseMutationRequest) -> bool {
        match request.operation() {
            SessionConsumerLeaseMutationOperation::Acquire { key, .. } => self.permits_key(key),
            SessionConsumerLeaseMutationOperation::Renew { lease, .. }
            | SessionConsumerLeaseMutationOperation::Release { lease } => {
                self.permits_key(lease.key())
            }
        }
    }

    fn permits_fenced_transition(&self, request: &FencedTransitionRequest) -> bool {
        self.permits_key(request.lease().key())
            && request
                .mutation()
                .record()
                .is_none_or(|record| self.permits_key(&record.key))
    }

    /// Check whether this already-authenticated authority grants one complete
    /// validated operation.
    ///
    /// The authority is minted only by a store-issued manifest after the
    /// transport has authenticated the consumer identity.  This method takes
    /// no scope argument, so callers cannot substitute a caller-selected
    /// cluster/configuration scope for the listener's separately validated
    /// request scope.  Consumers of [`SessionQuorumConsumer`] must invoke it
    /// before constructing any service execution or watch future.
    pub fn authorize_operation(
        &self,
        operation: &SessionConsumerOperation,
    ) -> Result<(), SessionConsumerRejection> {
        let authorized = match operation {
            SessionConsumerOperation::Capabilities
            | SessionConsumerOperation::PreflightRecordExpiry { .. }
            | SessionConsumerOperation::FencedTransitionCapability => true,
            // A single global replication cursor exposes otherwise foreign
            // tenants' mutation timing and ordering even when every change
            // item is filtered. Scoped consumers therefore cannot subscribe
            // until the protocol has an identity-and-scope-bound cursor.
            SessionConsumerOperation::Watch { .. } => false,
            SessionConsumerOperation::Get { key }
            | SessionConsumerOperation::AcquireLease { key, .. }
            | SessionConsumerOperation::ObserveFencedTransition { key } => self.permits_key(key),
            SessionConsumerOperation::CompareAndSet { op } => self.permits_compare_and_set(op),
            SessionConsumerOperation::DeleteFenced { lease }
            | SessionConsumerOperation::RefreshTtl { lease, .. }
            | SessionConsumerOperation::RenewLease { lease, .. }
            | SessionConsumerOperation::ReleaseLease { lease } => self.permits_key(lease.key()),
            SessionConsumerOperation::Batch { ops } => ops
                .iter()
                .all(|operation| self.permits_session_op(operation)),
            SessionConsumerOperation::ScanRestoreRecords { request } => {
                match (&request.scope.tenant, &request.scope.nf_kind) {
                    (Some(tenant), Some(nf_kind)) => {
                        self.allowed_scopes
                            .contains(&session_consumer_tenant_nf_fields_commitment(
                                tenant.as_str(),
                                nf_kind.as_str(),
                            ))
                    }
                    _ => false,
                }
            }
            SessionConsumerOperation::LeaseMutationStatus { request } => {
                self.permits_lease_mutation(request)
            }
            SessionConsumerOperation::CompareAndSetStatus { request } => {
                self.permits_compare_and_set(request.operation())
            }
            SessionConsumerOperation::FencedTransition { request }
            | SessionConsumerOperation::FencedTransitionStatus { request } => {
                self.permits_fenced_transition(request)
            }
        };
        authorized
            .then_some(())
            .ok_or(SessionConsumerRejection::Unauthorized)
    }
}

impl fmt::Debug for SessionConsumerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerRequest")
            .field("scope", &self.scope)
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .finish()
    }
}

/// Closed, wire-safe store error returned by a consumer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerStoreError {
    /// No live record exists.
    NotFound,
    /// A newer lease owner fenced this request.
    StaleFence,
    /// Compare-and-set did not match the current generation.
    CasConflict,
    /// A request ID was reused for another operation.
    RequestConflict,
    /// A mutation outcome is no longer known.
    OutcomeUnavailable,
    /// Topology authority is unavailable or no quorum is reachable.
    Unavailable,
    /// Input is structurally invalid.
    InvalidInput,
    /// The requested capability is deliberately absent.
    CapabilityNotSupported,
    /// A bounded watch requires coherent catch-up.
    WatchCatchUpRequired,
    /// The restore request or page is invalid.
    RestoreRejected,
    /// The restore cursor is stale.
    RestoreCursorStale,
    /// A restore scan exceeded its work or frame budget.
    RestoreBudgetExceeded,
    /// The requested TTL is invalid.
    InvalidTtl,
    /// The provided lease is held or expired.
    LeaseUnavailable,
    /// A payload exceeded the admitted size.
    PayloadTooLarge,
    /// The backend rejected protected data.
    ProtectedDataRejected,
}

impl From<StoreError> for SessionConsumerStoreError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound => Self::NotFound,
            StoreError::StaleFence | StoreError::TopologyAuthorityRevoked => Self::StaleFence,
            StoreError::CasConflict => Self::CasConflict,
            StoreError::CasIdempotencyConflict | StoreError::FencedTransitionRequestConflict => {
                Self::RequestConflict
            }
            // The closed generic store-error family has no specialized
            // fenced-transition exhaustion category. Preserve a fail-closed
            // capability response rather than widening that shared enum.
            StoreError::FencedTransitionHistoryFull
            | StoreError::FencedTransitionRetentionExhausted
            | StoreError::FencedTransitionStorageExhausted => Self::CapabilityNotSupported,
            StoreError::CasIdempotencyOutcomeUnavailable
            | StoreError::FencedTransitionOutcomeUnknown
            | StoreError::FencedTransitionRequestExpired
            | StoreError::BackendOperationOutcomeUnavailable => Self::OutcomeUnavailable,
            StoreError::BackendUnavailable(_) => Self::Unavailable,
            StoreError::CapabilityNotSupported(_) => Self::CapabilityNotSupported,
            StoreError::InvalidKey(_)
            | StoreError::InvalidReplicationSequence
            | StoreError::InvalidReplicationLogRange
            | StoreError::ReplicationLogPageTooLarge { .. }
            | StoreError::ReplicationLogCursorCompacted { .. }
            | StoreError::ReplicationOperationLimitExceeded
            | StoreError::RecordExpiryPreflightLimitExceeded
            | StoreError::InvalidRecordExpiry => Self::InvalidInput,
            StoreError::ReplicationWatchCatchUpRequired => Self::WatchCatchUpRequired,
            StoreError::InvalidSessionTtl => Self::InvalidTtl,
            StoreError::LeaseHeld | StoreError::LeaseExpired => Self::LeaseUnavailable,
            StoreError::Crypto(_) | StoreError::Serialization(_) => Self::ProtectedDataRejected,
            StoreError::PayloadTooLarge { .. } => Self::PayloadTooLarge,
            StoreError::InvalidRestoreScanRequest(_)
            | StoreError::InvalidRestoreScanResponse(_)
            | StoreError::RestoreScanPageTooLarge { .. } => Self::RestoreRejected,
            StoreError::RestoreScanCursorStale => Self::RestoreCursorStale,
            StoreError::RestoreScanWorkBudgetExceeded
            | StoreError::RestoreScanResponseTooLarge { .. } => Self::RestoreBudgetExceeded,
        }
    }
}

impl SessionConsumerStoreError {
    /// Convert a safe protocol error into the domain error expected by
    /// application-facing storage traits.
    pub fn into_store_error(self) -> StoreError {
        match self {
            Self::NotFound => StoreError::NotFound,
            Self::StaleFence => StoreError::StaleFence,
            Self::CasConflict => StoreError::CasConflict,
            Self::RequestConflict => StoreError::CasIdempotencyConflict,
            Self::OutcomeUnavailable => StoreError::BackendOperationOutcomeUnavailable,
            Self::Unavailable => {
                StoreError::BackendUnavailable("consumer quorum unavailable".into())
            }
            Self::InvalidInput => StoreError::InvalidKey("consumer request rejected".into()),
            Self::CapabilityNotSupported => {
                StoreError::CapabilityNotSupported("consumer capability unavailable".into())
            }
            Self::WatchCatchUpRequired => StoreError::ReplicationWatchCatchUpRequired,
            Self::RestoreRejected => {
                StoreError::InvalidRestoreScanRequest("consumer restore request rejected".into())
            }
            Self::RestoreCursorStale => StoreError::RestoreScanCursorStale,
            Self::RestoreBudgetExceeded => StoreError::RestoreScanWorkBudgetExceeded,
            Self::InvalidTtl => StoreError::InvalidSessionTtl,
            Self::LeaseUnavailable => StoreError::LeaseHeld,
            Self::PayloadTooLarge => StoreError::PayloadTooLarge { actual: 0, max: 0 },
            Self::ProtectedDataRejected => {
                StoreError::Crypto("consumer protected data rejected".into())
            }
        }
    }
}

/// Closed, wire-safe lease error returned by a consumer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerLeaseError {
    /// A caller-owned consumer request ID was reused for another operation.
    RequestConflict,
    /// Another consumer currently owns the lease.
    AlreadyHeld,
    /// The presented lease is expired.
    Expired,
    /// The presented fence is stale.
    StaleFence,
    /// The lease no longer exists.
    NotFound,
    /// The requested TTL is invalid.
    InvalidTtl,
    /// The mutation outcome is unknown and the lease must be treated as lost.
    OutcomeUnavailable,
    /// The quorum is unavailable and the lease must be treated as lost.
    Unavailable,
}

impl From<LeaseError> for SessionConsumerLeaseError {
    fn from(error: LeaseError) -> Self {
        match error {
            LeaseError::AlreadyHeld => Self::AlreadyHeld,
            LeaseError::Expired => Self::Expired,
            LeaseError::StaleFence => Self::StaleFence,
            LeaseError::NotFound => Self::NotFound,
            LeaseError::InvalidSessionTtl => Self::InvalidTtl,
            LeaseError::OperationOutcomeUnavailable => Self::OutcomeUnavailable,
            LeaseError::Backend(_) => Self::Unavailable,
        }
    }
}

impl SessionConsumerLeaseError {
    /// Convert a safe protocol lease error into the application trait error.
    pub fn into_lease_error(self) -> LeaseError {
        match self {
            Self::RequestConflict => LeaseError::Backend("consumer request conflict".into()),
            Self::AlreadyHeld => LeaseError::AlreadyHeld,
            Self::Expired => LeaseError::Expired,
            Self::StaleFence => LeaseError::StaleFence,
            Self::NotFound => LeaseError::NotFound,
            Self::InvalidTtl => LeaseError::InvalidSessionTtl,
            Self::OutcomeUnavailable => LeaseError::OperationOutcomeUnavailable,
            Self::Unavailable => LeaseError::Backend("consumer quorum unavailable".into()),
        }
    }
}

/// Exact persisted result for one ordinary lease mutation receipt.
///
/// This is distinct from a current lease observation.  A successful acquire
/// or renew is returned only from the matching durable consensus outcome, so
/// a later holder, expiry, or TTL change cannot be mistaken for the original
/// mutation result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerLeaseMutationResult {
    /// Exact guard persisted by the original acquire request.
    Acquire(LeaseGuard),
    /// Exact guard persisted by the original renew request.
    Renew(LeaseGuard),
    /// Exact successful release receipt.
    Release,
}

/// Exact read-only receipt status for an ordinary lease mutation.
///
/// `NotFound`, transport timeout, and quorum unavailability do not establish
/// that the original mutation was never transmitted.  Callers must therefore
/// keep the original request identity and body and remain fail-closed until a
/// matching [`Self::Recorded`] result is observed or their own ambiguity
/// fence expires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerLeaseMutationStatus {
    /// The exact persisted success or deterministic lease error.
    Recorded(Box<Result<SessionConsumerLeaseMutationResult, SessionConsumerLeaseError>>),
    /// The public request identity is durably bound to another exact body.
    RequestConflict,
    /// No matching receipt existed at the completed linearizable read barrier.
    NotFound,
}

/// Exact read-only receipt status for one prepared compare-and-set.
///
/// This projects the existing authoritative consensus outcome ledger. It is
/// not a current-row observation and never replays or proposes the mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerCompareAndSetStatus {
    /// The exact persisted success or deterministic compare-and-set failure.
    Recorded(SessionConsumerCompareAndSetReceiptOutcome),
    /// The public request identity is durably bound to another exact body.
    RequestConflict,
    /// No matching receipt existed at the completed linearizable read barrier.
    NotFound,
}

/// Fixed, payload-free projection of a recorded compare-and-set receipt.
///
/// The consensus ledger may retain an internal `CompareAndSetResult`, but a
/// receipt never serializes a current row or sealed payload back to a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerCompareAndSetReceiptOutcome {
    /// The exact CAS applied.
    Applied,
    /// The exact CAS predicate conflicted.
    Conflict,
    /// The exact CAS was deterministically rejected.
    Rejected(SessionConsumerStoreError),
}

/// Explicit classification for a request that might have crossed its effect
/// point but cannot be confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionConsumerOutcomeUnknown {
    /// An application state mutation may have committed.
    Mutation {
        /// Stable caller-retained identity used for exact status recovery.
        request_id: SessionConsumerRequestId,
    },
    /// A lease mutation may have committed; the current guard is lost.
    Lease,
}

/// Safe deterministic error retained by a fenced-transition receipt.
///
/// This is intentionally a closed projection rather than `StoreError`: a
/// receipt must never serialize backend-provided diagnostic text to a
/// consumer transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerFencedTransitionError {
    /// A deterministic store result represented by the safe consumer error set.
    Store(SessionConsumerStoreError),
    /// The public identity is permanently bound to another body.
    RequestConflict,
    /// The exact retained outcome elapsed.
    Expired,
    /// The permanent receipt ledger cannot bind a new identity.
    HistoryFull,
    /// Logical time cannot retain a complete result window.
    RetentionExhausted,
    /// The deterministic transition receipt could not be retained.
    StorageExhausted,
}

impl From<StoreError> for SessionConsumerFencedTransitionError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::FencedTransitionRequestConflict => Self::RequestConflict,
            StoreError::FencedTransitionRequestExpired => Self::Expired,
            StoreError::FencedTransitionHistoryFull => Self::HistoryFull,
            StoreError::FencedTransitionRetentionExhausted => Self::RetentionExhausted,
            StoreError::FencedTransitionStorageExhausted => Self::StorageExhausted,
            error => Self::Store(SessionConsumerStoreError::from(error)),
        }
    }
}

/// Exact consumer-safe status of a fenced transition request/body pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerFencedTransitionStatus {
    /// A success or deterministic error remains recoverable.
    Recorded(Box<Result<FencedTransitionOutcome, SessionConsumerFencedTransitionError>>),
    /// The identity is bound to another body.
    RequestConflict,
    /// The exact recovery window elapsed.
    Expired,
    /// The receipt ledger is full for a fresh identity.
    HistoryFull,
    /// The retention horizon is exhausted for a fresh identity.
    RetentionExhausted,
    /// No request/body receipt existed at the read barrier.
    NotFound,
}

impl From<FencedTransitionStatus> for SessionConsumerFencedTransitionStatus {
    fn from(status: FencedTransitionStatus) -> Self {
        match status {
            FencedTransitionStatus::Recorded(result) => Self::Recorded(Box::new(
                result.map_err(SessionConsumerFencedTransitionError::from),
            )),
            FencedTransitionStatus::RequestConflict => Self::RequestConflict,
            FencedTransitionStatus::Expired => Self::Expired,
            FencedTransitionStatus::HistoryFull => Self::HistoryFull,
            FencedTransitionStatus::RetentionExhausted => Self::RetentionExhausted,
            FencedTransitionStatus::NotFound => Self::NotFound,
        }
    }
}

/// Least-authority committed-change projection for application consumers.
///
/// This is intentionally not a replication entry: it omits replay payloads,
/// lease credentials, absolute deadlines, transaction IDs, and raw
/// replication operation trees.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerChange {
    sequence: u64,
    changes: Vec<SessionConsumerChangeItem>,
}

/// One affected session key within a [`SessionConsumerChange`].
///
/// This is a deliberately coarse projection. It is not a lease credential,
/// fence, expiry, owner, record payload, replication transaction, or replay
/// instruction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerChangeItem {
    key: SessionKey,
    kind: SessionConsumerChangeKind,
}

impl SessionConsumerChange {
    /// Committed change sequence used only as a consumer watch cursor.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Coarse affected keys in their committed batch order.
    ///
    /// One replication sequence can contain a bounded nested batch, so the
    /// consumer projection preserves every leaf change in one envelope rather
    /// than dropping all but the first key.
    pub fn changes(&self) -> &[SessionConsumerChangeItem] {
        self.changes.as_slice()
    }
}

impl fmt::Debug for SessionConsumerChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerChange(<redacted>)")
    }
}

impl SessionConsumerChangeItem {
    /// Session key affected by this committed leaf change.
    pub const fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Coarse application-visible change kind.
    pub const fn kind(&self) -> SessionConsumerChangeKind {
        self.kind
    }
}

impl fmt::Debug for SessionConsumerChangeItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerChangeItem(<redacted>)")
    }
}

/// Coarse committed change class exposed by [`SessionConsumerChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionConsumerChangeKind {
    /// A session record was created or replaced.
    RecordWritten,
    /// A session record was deleted.
    RecordDeleted,
    /// A session record TTL changed.
    RecordTtlRefreshed,
    /// A session lease was acquired.
    LeaseAcquired,
    /// A session lease was renewed.
    LeaseRenewed,
    /// A session lease was released.
    LeaseReleased,
}

#[cfg(test)]
pub(crate) fn session_consumer_change(
    entry: &crate::ReplicationEntry,
) -> Result<SessionConsumerChange, StoreError> {
    // A replication batch is a recursive replay instruction. Flatten it
    // iteratively so a historical bounded nested batch remains faithfully
    // observable without exposing that instruction tree at the consumer
    // boundary. Count both batch containers and leaves under the existing
    // SDK-wide admission cap; a malformed stored entry therefore fails the
    // watch closed instead of allocating an unbounded projection.
    let mut pending = vec![&entry.op];
    let mut visited = 0_usize;
    let mut changes = Vec::with_capacity(MAX_REPLICATION_OPERATIONS_PER_ENTRY);
    while let Some(operation) = pending.pop() {
        visited = visited
            .checked_add(1)
            .ok_or(StoreError::ReplicationOperationLimitExceeded)?;
        if visited > MAX_REPLICATION_OPERATIONS_PER_ENTRY {
            return Err(StoreError::ReplicationOperationLimitExceeded);
        }
        let item = match operation {
            crate::ReplicationOp::CompareAndSet { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::RecordWritten,
            }),
            crate::ReplicationOp::DeleteFenced { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::RecordDeleted,
            }),
            crate::ReplicationOp::RefreshTtl { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::RecordTtlRefreshed,
            }),
            crate::ReplicationOp::AcquireLease { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::LeaseAcquired,
            }),
            crate::ReplicationOp::RenewLease { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::LeaseRenewed,
            }),
            crate::ReplicationOp::ReleaseLease { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::LeaseReleased,
            }),
            crate::ReplicationOp::Batch { ops } => {
                pending.extend(ops.iter().rev());
                None
            }
        };
        if let Some(item) = item {
            changes.push(item);
        }
    }
    Ok(SessionConsumerChange {
        sequence: entry.sequence,
        changes,
    })
}

/// Closed rejection before an operation reaches the consensus state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionConsumerRejection {
    /// Cluster/configuration/epoch differs from the live quorum scope.
    ScopeMismatch,
    /// The typed request violated a fixed contract bound.
    MalformedRequest,
    /// The mTLS identity is not authorized as a consumer.
    Unauthorized,
    /// The server cannot dispatch the request within its bound.
    Unavailable,
}

/// Safe result of one batch slot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SessionConsumerBatchResult {
    /// Point-read slot result.
    Get(Result<Option<StoredSessionRecord>, SessionConsumerStoreError>),
    /// Compare-and-set slot result.
    CompareAndSet(Result<CompareAndSetResult, SessionConsumerStoreError>),
    /// Delete slot result.
    DeleteFenced(Result<(), SessionConsumerStoreError>),
    /// TTL-refresh slot result.
    RefreshTtl(Result<(), SessionConsumerStoreError>),
}

impl fmt::Debug for SessionConsumerBatchResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerBatchResult(<redacted>)")
    }
}

/// Typed response from one stateless consumer operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "response",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerResponse {
    /// Capability declaration.
    Capabilities(BackendCapabilities),
    /// Point-read result.
    Get(Result<Option<StoredSessionRecord>, SessionConsumerStoreError>),
    /// Record-expiry preflight result.
    PreflightRecordExpiry(Result<(), SessionConsumerStoreError>),
    /// Compare-and-set result.
    CompareAndSet(Result<CompareAndSetResult, SessionConsumerStoreError>),
    /// Delete result.
    DeleteFenced(Result<(), SessionConsumerStoreError>),
    /// TTL-refresh result.
    RefreshTtl(Result<(), SessionConsumerStoreError>),
    /// Batch result.
    Batch(Result<Vec<SessionConsumerBatchResult>, SessionConsumerStoreError>),
    /// Restore scan result.
    ScanRestoreRecords(Result<RestoreScanPage, SessionConsumerStoreError>),
    /// Watch admission result; entries follow as separately framed messages.
    WatchOpened,
    /// Lease acquisition result.
    AcquireLease(Result<LeaseGuard, SessionConsumerLeaseError>),
    /// Lease renewal result.
    RenewLease(Result<LeaseGuard, SessionConsumerLeaseError>),
    /// Lease release result.
    ReleaseLease(Result<(), SessionConsumerLeaseError>),
    /// Exact read-only receipt status for an ordinary lease mutation.
    LeaseMutationStatus(Result<SessionConsumerLeaseMutationStatus, SessionConsumerStoreError>),
    /// Exact read-only receipt status for a prepared compare-and-set.
    CompareAndSetStatus(Result<SessionConsumerCompareAndSetStatus, SessionConsumerStoreError>),
    /// Exact unanimous atomic-transition capability result.
    FencedTransitionCapability(Result<AtomicFencedTransitionCapability, SessionConsumerStoreError>),
    /// Exact-key record and fence-floor observation.
    ObserveFencedTransition(Result<FencedTransitionObservation, SessionConsumerStoreError>),
    /// Atomic lease-and-record transition result.
    FencedTransition(Result<FencedTransitionOutcome, SessionConsumerFencedTransitionError>),
    /// Exact retained transition status.
    FencedTransitionStatus(
        Result<SessionConsumerFencedTransitionStatus, SessionConsumerStoreError>,
    ),
    /// A mutation outcome is ambiguous and must never be automatically replayed.
    OutcomeUnknown(SessionConsumerOutcomeUnknown),
    /// A request was rejected before dispatch.
    Rejected(SessionConsumerRejection),
}

impl fmt::Debug for SessionConsumerResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Capabilities(_) => "Capabilities",
            Self::Get(_) => "Get",
            Self::PreflightRecordExpiry(_) => "PreflightRecordExpiry",
            Self::CompareAndSet(_) => "CompareAndSet",
            Self::DeleteFenced(_) => "DeleteFenced",
            Self::RefreshTtl(_) => "RefreshTtl",
            Self::Batch(_) => "Batch",
            Self::ScanRestoreRecords(_) => "ScanRestoreRecords",
            Self::WatchOpened => "WatchOpened",
            Self::AcquireLease(_) => "AcquireLease",
            Self::RenewLease(_) => "RenewLease",
            Self::ReleaseLease(_) => "ReleaseLease",
            Self::LeaseMutationStatus(_) => "LeaseMutationStatus",
            Self::CompareAndSetStatus(_) => "CompareAndSetStatus",
            Self::FencedTransitionCapability(_) => "FencedTransitionCapability",
            Self::ObserveFencedTransition(_) => "ObserveFencedTransition",
            Self::FencedTransition(_) => "FencedTransition",
            Self::FencedTransitionStatus(_) => "FencedTransitionStatus",
            Self::OutcomeUnknown(_) => "OutcomeUnknown",
            Self::Rejected(_) => "Rejected",
        };
        formatter.write_str(name)
    }
}

/// Quorum-side typed application service used by the dedicated consumer
/// transport.
///
/// Implementations must receive a store-manifest-issued authorization from
/// their inbound boundary, reject a scope mismatch before backend work, and
/// route mutations through the durable quorum leader path. This trait intentionally cannot
/// express any consensus RPC, member/topology mutation, snapshot, or raw
/// replication append/rebuild request.
#[async_trait]
pub trait SessionQuorumConsumer: Send + Sync {
    /// Execute one authenticated, scope-bound consumer request.
    async fn execute(
        &self,
        authorization: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse;

    /// Open a bounded committed-change watch after authenticated scope checks.
    async fn watch(
        &self,
        authorization: &SessionConsumerAuthorization,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    >;
}

/// Convert an application batch result into its wire-safe counterpart.
pub fn session_consumer_batch_result(result: SessionOpResult) -> SessionConsumerBatchResult {
    match result {
        SessionOpResult::Get(result) => {
            SessionConsumerBatchResult::Get(result.map_err(SessionConsumerStoreError::from))
        }
        SessionOpResult::CompareAndSet(result) => SessionConsumerBatchResult::CompareAndSet(
            result.map_err(SessionConsumerStoreError::from),
        ),
        SessionOpResult::DeleteFenced(result) => SessionConsumerBatchResult::DeleteFenced(
            result.map_err(SessionConsumerStoreError::from),
        ),
        SessionOpResult::RefreshTtl(result) => {
            SessionConsumerBatchResult::RefreshTtl(result.map_err(SessionConsumerStoreError::from))
        }
    }
}

/// Convert a consumer batch result into the application-facing result.
pub fn session_consumer_batch_result_into_store(
    result: SessionConsumerBatchResult,
) -> SessionOpResult {
    match result {
        SessionConsumerBatchResult::Get(result) => {
            SessionOpResult::Get(result.map_err(SessionConsumerStoreError::into_store_error))
        }
        SessionConsumerBatchResult::CompareAndSet(result) => SessionOpResult::CompareAndSet(
            result.map_err(SessionConsumerStoreError::into_store_error),
        ),
        SessionConsumerBatchResult::DeleteFenced(result) => SessionOpResult::DeleteFenced(
            result.map_err(SessionConsumerStoreError::into_store_error),
        ),
        SessionConsumerBatchResult::RefreshTtl(result) => {
            SessionOpResult::RefreshTtl(result.map_err(SessionConsumerStoreError::into_store_error))
        }
    }
}

/// Derive the durable consumer-request binding ID from an authenticated
/// identity and caller-owned request ID.
///
/// This deliberately excludes the operation commitment: the resulting ID is
/// used for a small quorum-durable binding command, whose payload commitment
/// makes reuse of this caller ID for a different request a closed conflict.
pub(crate) fn derive_consumer_request_binding_id(
    identity: &SessionConsumerIdentity,
    request: &SessionConsumerRequest,
) -> SessionConsensusRequestId {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/request-binding/v1\\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    // Keep this stable across a configuration-epoch transition. The marker
    // payload commits the exact scope, so an old caller ID can only recover
    // its original binding or receive a closed conflict; it cannot become a
    // fresh mutation in a successor scope.
    digest.update(request.scope().consensus_identity().cluster_id().as_bytes());
    digest.update(request.request_id().as_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut request_bytes = [0_u8; SESSION_CONSUMER_REQUEST_ID_BYTES];
    request_bytes.copy_from_slice(&hash[..SESSION_CONSUMER_REQUEST_ID_BYTES]);
    SessionConsensusRequestId::from_bytes(request_bytes)
}

/// Hash the full serialized request shape without exposing protected contents.
pub(crate) fn consumer_request_commitment(
    request: &SessionConsumerRequest,
) -> Result<[u8; 32], SessionConsumerRejection> {
    use sha2::{Digest, Sha256};

    let encoded =
        serde_json::to_vec(request).map_err(|_| SessionConsumerRejection::MalformedRequest)?;
    #[cfg(test)]
    {
        CONSUMER_REQUEST_COMMITMENT_V2_SERIALIZATIONS.fetch_add(1, Ordering::Relaxed);
        CONSUMER_REQUEST_COMMITMENT_V2_SERIALIZED_BYTES.fetch_add(encoded.len(), Ordering::Relaxed);
    }
    let mut digest = Sha256::new();
    // Keep the ordinary request commitment domain at v2 after the removed
    // prepared wire field changed the serialized shape. A reused legacy
    // binding can therefore only conflict closed; no v1 interpretation is
    // accepted.
    digest.update(b"openpacketcore/session-consumer/request-commitment/v2\\0");
    digest.update(encoded);
    Ok(digest.finalize().into())
}

/// Test-only accounting for whole-request v2 commitment serialization. The
/// production path retains no metrics labels, request IDs, or payload copies.
#[cfg(test)]
pub(crate) static CONSUMER_REQUEST_COMMITMENT_V2_SERIALIZATIONS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
pub(crate) static CONSUMER_REQUEST_COMMITMENT_V2_SERIALIZED_BYTES: AtomicUsize =
    AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn reset_consumer_request_commitment_v2_test_counters() {
    CONSUMER_REQUEST_COMMITMENT_V2_SERIALIZATIONS.store(0, Ordering::Relaxed);
    CONSUMER_REQUEST_COMMITMENT_V2_SERIALIZED_BYTES.store(0, Ordering::Relaxed);
}

/// Derive the operation-specific durable consensus request ID from an
/// authenticated identity, the complete request commitment, and bounded batch
/// slot. The full parent request shape prevents a changed batch from moving a
/// mutation onto an unrelated slot's durable outcome.
pub fn derive_consumer_consensus_request_id(
    identity: &SessionConsumerIdentity,
    request: &SessionConsumerRequest,
    slot: u16,
) -> Result<SessionConsensusRequestId, SessionConsumerRejection> {
    let commitment = consumer_request_commitment(request)?;
    Ok(derive_consumer_consensus_request_id_from_commitment(
        identity, commitment, slot,
    ))
}

/// Derive an operation receipt ID from one already-authenticated full request
/// commitment. Receipt lookup uses this to avoid serializing the retained body
/// a second time after the service has validated it.
pub(crate) fn derive_consumer_consensus_request_id_from_commitment(
    identity: &SessionConsumerIdentity,
    commitment: [u8; 32],
    slot: u16,
) -> SessionConsensusRequestId {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/operation-request-id/v2\\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    digest.update(commitment);
    digest.update(slot.to_be_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut request_bytes = [0_u8; SESSION_CONSUMER_REQUEST_ID_BYTES];
    request_bytes.copy_from_slice(&hash[..SESSION_CONSUMER_REQUEST_ID_BYTES]);
    SessionConsensusRequestId::from_bytes(request_bytes)
}

/// Rebuild a transition for the internal receipt ledger without exposing that
/// ledger's global identity domain to consumers.
///
/// The outer scope is still enforced at every proposal/read boundary. Its
/// stable cluster component isolates unrelated deployments while deliberately
/// excluding changing configuration and epoch values: a retry or status read
/// remains recoverable after an authorized authority rollover. The body is
/// excluded so the existing transition receipt binding can reject a reused ID
/// with a different body as `RequestConflict`.
pub(crate) fn derive_consumer_fenced_transition_request(
    identity: &SessionConsumerIdentity,
    scope: SessionConsumerScope,
    request: &FencedTransitionRequest,
) -> Result<FencedTransitionRequest, SessionConsumerRejection> {
    use sha2::{Digest, Sha256};

    request
        .validate()
        .map_err(|_| SessionConsumerRejection::MalformedRequest)?;
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/fenced-transition-id/v1\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    digest.update(scope.consensus_identity().cluster_id().as_bytes());
    digest.update(request.request_id().as_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut internal_id = [0_u8; FENCED_TRANSITION_REQUEST_ID_BYTES];
    internal_id.copy_from_slice(&hash[..FENCED_TRANSITION_REQUEST_ID_BYTES]);
    // The public transition contract reserves the all-zero ID. A truncated
    // digest can equal that value in principle, so keep the derivation total
    // instead of probabilistically rejecting an otherwise valid request.
    if internal_id.iter().all(|byte| *byte == 0) {
        internal_id[FENCED_TRANSITION_REQUEST_ID_BYTES - 1] = 1;
    }
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes(internal_id),
        request.lease().clone(),
        request.mutation().clone(),
    )
    .map_err(|_| SessionConsumerRejection::MalformedRequest)
}

/// Marker imported by stateless clients to make accidental use of
/// [`crate::SessionBackend`] explicit at composition time.
///
/// A consumer client deliberately composes the application subset instead of
/// implementing `SessionBackend` or [`crate::SessionLeaseManager`]: the former carries
/// legacy replication reconstruction authority and the latter would hide
/// freshly generated retry IDs. Lease calls on this boundary therefore always
/// require a caller-owned [`SessionConsumerRequestId`].
pub trait StatelessSessionConsumer: Send + Sync {}

#[cfg(test)]
mod tests {
    use super::{
        derive_consumer_consensus_request_id, derive_consumer_fenced_transition_request,
        SessionConsumerAuthorizationGrant, SessionConsumerAuthorizationGrantError,
        SessionConsumerAuthorizationManifestError, SessionConsumerFencedTransitionError,
        SessionConsumerFencedTransitionStatus, SessionConsumerIdentity, SessionConsumerOperation,
        SessionConsumerRejection, SessionConsumerRequest, SessionConsumerRequestId,
        SessionConsumerRoster, SessionConsumerRosterError, SessionConsumerScope,
        SessionConsumerTenantNfScope, SESSION_CONSUMER_IDENTITY_MAX_BYTES,
    };
    use crate::{
        FenceToken, FencedTransitionLease, FencedTransitionMutation, FencedTransitionRequest,
        FencedTransitionRequestId, FencedTransitionStatus, Generation, OwnerId,
        QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
        ReplicaId, ReplicaTlsIdentity, RestoreScanRequest, RestoreScanScope,
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity, SessionConsensusNodeId,
        SessionKey, SessionKeyType, SessionOp, StableId, StoreError, QUORUM_TOPOLOGY_MAX_MEMBERS,
    };
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};
    use std::collections::BTreeSet;
    use std::time::Duration;

    fn scope(configuration: u8, epoch: u64) -> SessionConsumerScope {
        SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([configuration; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).expect("non-zero configuration epoch"),
        ))
    }

    fn roster_scope(cluster: u8, configuration: u8, epoch: u64) -> SessionConsumerScope {
        SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([cluster; 32]),
            SessionConsensusConfigurationId::from_bytes([configuration; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).expect("non-zero configuration epoch"),
        ))
    }

    fn roster_nodes(values: &[u64]) -> BTreeSet<SessionConsensusNodeId> {
        values
            .iter()
            .copied()
            .map(|value| SessionConsensusNodeId::new(value).expect("valid roster node ID"))
            .collect()
    }

    fn roster_descriptor(node: u64, tls_identity: impl Into<String>) -> QuorumReplicaDescriptor {
        QuorumReplicaDescriptor::new(
            ReplicaId::new(format!("consumer-roster-node-{node}")).expect("replica ID"),
            ReplicaEndpoint::new(format!("consumer-roster-node-{node}.test.invalid"), 7443)
                .expect("endpoint"),
            ReplicaTlsIdentity::new(tls_identity).expect("TLS identity"),
            ReplicaFailureDomain::new(format!("consumer-roster-zone-{node}"))
                .expect("failure domain"),
            ReplicaBackingIdentity::new(format!("consumer-roster-backing-{node}"))
                .expect("backing identity"),
        )
    }

    fn roster_descriptors() -> Vec<(u64, QuorumReplicaDescriptor)> {
        vec![
            (
                1,
                roster_descriptor(1, "spiffe://test.invalid/consumer-roster/one"),
            ),
            (
                2,
                roster_descriptor(2, "spiffe://test.invalid/consumer-roster/two"),
            ),
        ]
    }

    fn authorization_fixture() -> (super::SessionConsumerAuthorization, SessionKey) {
        let scope = roster_scope(9, 8, 7);
        let node_id = SessionConsensusNodeId::new(1).expect("roster node");
        let roster = SessionConsumerRoster::try_new(
            scope,
            &roster_nodes(&[1]),
            vec![(
                (node_id.get()),
                roster_descriptor(1, "spiffe://test.invalid/consumer-roster/voter"),
            )],
        )
        .expect("validated roster");
        let identity = SessionConsumerIdentity::new(
            "spiffe://test.invalid/tenant/tenant-a/ns/default/sa/app/nf/smf/instance/one",
        )
        .expect("consumer identity");
        let grant = SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(identity.as_str()).expect("canonical SPIFFE ID"),
            [SessionConsumerTenantNfScope::new(
                TenantId::from_static("tenant-a"),
                NetworkFunctionKind::smf(),
            )],
        )
        .expect("consumer grant");
        let manifest = roster
            .authorization_manifest(node_id, [grant])
            .expect("authorization manifest");
        let key = SessionKey {
            tenant: TenantId::from_static("tenant-a"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"authorized-key")).expect("stable ID"),
        };
        (
            manifest.authorize(&identity).expect("authorization token"),
            key,
        )
    }

    #[test]
    fn explicit_grants_reject_duplicate_scopes_and_identities() {
        let identity = SpiffeId::new(
            "spiffe://test.invalid/tenant/tenant-a/ns/default/sa/app/nf/smf/instance/one",
        )
        .expect("canonical SPIFFE ID");
        let scope = SessionConsumerTenantNfScope::new(
            TenantId::from_static("tenant-a"),
            NetworkFunctionKind::smf(),
        );
        assert!(matches!(
            SessionConsumerAuthorizationGrant::try_new(identity.clone(), [scope.clone(), scope]),
            Err(SessionConsumerAuthorizationGrantError::DuplicateScope)
        ));

        let roster_scope = roster_scope(9, 8, 7);
        let node_id = SessionConsensusNodeId::new(1).expect("roster node");
        let roster = SessionConsumerRoster::try_new(
            roster_scope,
            &roster_nodes(&[1]),
            vec![(
                1,
                roster_descriptor(1, "spiffe://test.invalid/consumer-roster/voter"),
            )],
        )
        .expect("validated roster");
        let grant = || {
            SessionConsumerAuthorizationGrant::try_new(
                identity.clone(),
                [SessionConsumerTenantNfScope::new(
                    TenantId::from_static("tenant-a"),
                    NetworkFunctionKind::smf(),
                )],
            )
            .expect("grant")
        };
        assert!(matches!(
            roster.authorization_manifest(node_id, [grant(), grant()]),
            Err(SessionConsumerAuthorizationManifestError::DuplicateIdentity)
        ));
    }

    #[test]
    fn authorization_requires_exact_scope_and_denies_global_watch() {
        let (authorization, key) = authorization_fixture();
        let foreign = SessionKey {
            tenant: TenantId::from_static("tenant-z"),
            ..key.clone()
        };
        assert_eq!(
            authorization.authorize_operation(&SessionConsumerOperation::Get {
                key: foreign.clone()
            }),
            Err(SessionConsumerRejection::Unauthorized),
            "an ungranted third tenant is never inferred from the SPIFFE ID"
        );
        assert_eq!(
            authorization.authorize_operation(&SessionConsumerOperation::Batch {
                ops: vec![
                    SessionOp::Get { key: key.clone() },
                    SessionOp::Get {
                        key: foreign.clone()
                    }
                ],
            }),
            Err(SessionConsumerRejection::Unauthorized),
            "every bounded batch slot is checked before dispatch"
        );
        assert_eq!(
            authorization.authorize_operation(&SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest {
                    scope: RestoreScanScope {
                        tenant: Some(key.tenant.clone()),
                        ..RestoreScanScope::all()
                    },
                    cursor: None,
                    limit: 1,
                },
            }),
            Err(SessionConsumerRejection::Unauthorized),
            "restore requires both exact tenant and NF instead of a prefix filter"
        );
        assert!(authorization
            .authorize_operation(&SessionConsumerOperation::ScanRestoreRecords {
                request: RestoreScanRequest {
                    scope: RestoreScanScope {
                        tenant: Some(key.tenant.clone()),
                        nf_kind: Some(key.nf_kind.clone()),
                        ..RestoreScanScope::all()
                    },
                    cursor: None,
                    limit: 1,
                },
            })
            .is_ok());

        assert_eq!(
            authorization.authorize_operation(&SessionConsumerOperation::Watch {
                start_sequence: 77,
            }),
            Err(SessionConsumerRejection::Unauthorized),
            "a global sequence would reveal foreign-tenant mutation timing even after item filtering"
        );
    }

    #[test]
    fn consumer_roster_is_sorted_and_commits_every_scope_and_member_component() {
        let scope = roster_scope(1, 2, 3);
        let expected_nodes = roster_nodes(&[1, 2]);
        let roster = SessionConsumerRoster::try_new(
            scope,
            &expected_nodes,
            vec![
                (
                    2,
                    roster_descriptor(2, "spiffe://test.invalid/consumer-roster/two"),
                ),
                (
                    1,
                    roster_descriptor(1, "spiffe://test.invalid/consumer-roster/one"),
                ),
            ],
        )
        .expect("complete roster");
        let reordered =
            SessionConsumerRoster::try_new(scope, &expected_nodes, roster_descriptors())
                .expect("reordered complete roster");

        assert_eq!(
            roster
                .consensus_members()
                .map(|member| (member.node_id().get(), member.tls_identity().to_owned()))
                .collect::<Vec<_>>(),
            vec![
                (1, "spiffe://test.invalid/consumer-roster/one".to_owned()),
                (2, "spiffe://test.invalid/consumer-roster/two".to_owned()),
            ]
        );
        assert_eq!(roster.roster_commitment(), reordered.roster_commitment());
        let commitment = roster.roster_commitment();

        for changed_scope in [
            roster_scope(4, 2, 3),
            roster_scope(1, 5, 3),
            roster_scope(1, 2, 6),
        ] {
            assert_ne!(
                commitment,
                SessionConsumerRoster::try_new(
                    changed_scope,
                    &expected_nodes,
                    roster_descriptors(),
                )
                .expect("changed scope roster")
                .roster_commitment()
            );
        }
        assert_ne!(
            commitment,
            SessionConsumerRoster::try_new(
                scope,
                &expected_nodes,
                vec![
                    (
                        1,
                        roster_descriptor(1, "spiffe://test.invalid/consumer-roster/replaced"),
                    ),
                    (
                        2,
                        roster_descriptor(2, "spiffe://test.invalid/consumer-roster/two"),
                    ),
                ],
            )
            .expect("changed TLS roster")
            .roster_commitment()
        );
        let changed_nodes = roster_nodes(&[1, 7]);
        assert_ne!(
            commitment,
            SessionConsumerRoster::try_new(
                scope,
                &changed_nodes,
                vec![
                    (
                        1,
                        roster_descriptor(1, "spiffe://test.invalid/consumer-roster/one"),
                    ),
                    (
                        7,
                        roster_descriptor(7, "spiffe://test.invalid/consumer-roster/two"),
                    ),
                ],
            )
            .expect("changed node roster")
            .roster_commitment()
        );
        assert!(!format!("{roster:?}").contains("consumer-roster/one"));
        assert_eq!(
            format!("{:?}", roster.roster_commitment()),
            "SessionConsumerRosterCommitment(<redacted>)"
        );
    }

    #[test]
    fn consumer_roster_rejects_invalid_duplicate_and_scope_mismatched_bindings() {
        let scope = roster_scope(1, 2, 3);
        let one_member = roster_nodes(&[1]);
        let two_members = roster_nodes(&[1, 2]);
        let valid = roster_descriptor(1, "spiffe://test.invalid/consumer-roster/one");

        assert!(matches!(
            SessionConsumerRoster::try_new(scope, &BTreeSet::new(), std::iter::empty(),),
            Err(SessionConsumerRosterError::Empty)
        ));
        let oversized_values = (1..=(QUORUM_TOPOLOGY_MAX_MEMBERS as u64 + 1)).collect::<Vec<_>>();
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &roster_nodes(&oversized_values),
                std::iter::empty(),
            ),
            Err(SessionConsumerRosterError::MemberCountTooLarge)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &one_member,
                vec![
                    (1, valid.clone()),
                    (
                        1,
                        roster_descriptor(1, "spiffe://test.invalid/consumer-roster/other"),
                    ),
                ],
            ),
            Err(SessionConsumerRosterError::DuplicateNodeId)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &two_members,
                vec![(1, valid.clone()), (2, valid.clone())],
            ),
            Err(SessionConsumerRosterError::DuplicateTlsIdentity)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(scope, &one_member, vec![(0, valid.clone())],),
            Err(SessionConsumerRosterError::InvalidNodeId)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &one_member,
                vec![(i64::MAX as u64 + 1, valid.clone())],
            ),
            Err(SessionConsumerRosterError::InvalidNodeId)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(
                scope,
                &one_member,
                vec![(
                    1,
                    roster_descriptor(1, "x".repeat(SESSION_CONSUMER_IDENTITY_MAX_BYTES + 1),),
                )],
            ),
            Err(SessionConsumerRosterError::InvalidTlsIdentity)
        ));
        assert!(matches!(
            SessionConsumerRoster::try_new(scope, &two_members, vec![(1, valid)]),
            Err(SessionConsumerRosterError::ScopeMismatch)
        ));
    }

    fn transition(id: u8) -> FencedTransitionRequest {
        let key = SessionKey {
            tenant: TenantId::from_static("consumer-transition-test"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"transition-id")).expect("stable ID"),
        };
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([id; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("consumer-transition-owner").expect("owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("transition")
    }

    #[test]
    fn durable_request_identity_is_stable_and_consumer_bound() {
        let request_id = SessionConsumerRequestId::from_bytes([7; 16]);
        let scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([2; 32]),
            SessionConsensusConfigurationEpoch::new(3).expect("non-zero configuration epoch"),
        ));
        let request =
            SessionConsumerRequest::new(scope, request_id, SessionConsumerOperation::Capabilities);
        let changed_request = SessionConsumerRequest::new(
            scope,
            request_id,
            SessionConsumerOperation::Watch { start_sequence: 7 },
        );
        let first = SessionConsumerIdentity::new("spiffe://test.example/consumer/first")
            .expect("valid first consumer identity");
        let second = SessionConsumerIdentity::new("spiffe://test.example/consumer/second")
            .expect("valid second consumer identity");

        assert_eq!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&first, &request, 0),
            "an explicit retry must preserve the durable request identity"
        );
        assert_ne!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&second, &request, 0),
            "one consumer cannot collide with another consumer's retry domain"
        );
        assert_ne!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&first, &request, 1),
            "batch slots must retain independently durable outcomes"
        );
        assert_ne!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&first, &changed_request, 0),
            "a changed full request shape cannot reuse a slot outcome"
        );
    }

    #[test]
    fn consumer_identity_and_request_debug_are_redacted() {
        let identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/secret")
            .expect("valid consumer identity");
        let request_id = SessionConsumerRequestId::from_bytes([9; 16]);
        let scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([7; 32]),
            SessionConsensusConfigurationId::from_bytes([8; 32]),
            SessionConsensusConfigurationEpoch::new(9).expect("non-zero configuration epoch"),
        ));

        assert!(!format!("{identity:?}").contains(identity.as_str()));
        assert!(!format!("{request_id:?}").contains("090909"));
        assert_eq!(format!("{scope:?}"), "SessionConsumerScope(<redacted>)");
    }

    #[test]
    fn consumer_request_rejects_unknown_wire_fields() {
        let request = SessionConsumerRequest::new(
            SessionConsumerScope::new(SessionConsensusIdentity::new(
                SessionConsensusClusterId::from_bytes([1; 32]),
                SessionConsensusConfigurationId::from_bytes([2; 32]),
                SessionConsensusConfigurationEpoch::new(3).expect("non-zero configuration epoch"),
            )),
            SessionConsumerRequestId::from_bytes([4; 16]),
            SessionConsumerOperation::Watch { start_sequence: 5 },
        );
        let encoded = serde_json::to_value(request).expect("request encodes");
        let mut root_unknown = encoded.clone();
        let serde_json::Value::Object(fields) = &mut root_unknown else {
            panic!("request is an object");
        };
        fields.insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SessionConsumerRequest>(root_unknown).is_err());

        let mut legacy_prepared_authority = encoded.clone();
        let serde_json::Value::Object(fields) = &mut legacy_prepared_authority else {
            panic!("request is an object");
        };
        fields.insert("prepared_authority".into(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<SessionConsumerRequest>(legacy_prepared_authority).is_err(),
            "legacy prepared wire authority is an unknown field"
        );

        let mut operation_unknown = encoded;
        let serde_json::Value::Object(fields) = &mut operation_unknown else {
            panic!("request is an object");
        };
        let operation = fields
            .get_mut("operation")
            .and_then(serde_json::Value::as_object_mut)
            .expect("operation is an object");
        operation.insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SessionConsumerRequest>(operation_unknown).is_err());
    }

    #[test]
    fn fenced_transition_identity_is_consumer_bound_and_rollover_stable() {
        let first = SessionConsumerIdentity::new("spiffe://test.example/consumer/first")
            .expect("first identity");
        let second = SessionConsumerIdentity::new("spiffe://test.example/consumer/second")
            .expect("second identity");
        let request = transition(0x55);
        let successor_scope = scope(3, 2);
        let first_scope = scope(2, 1);

        let first_internal =
            derive_consumer_fenced_transition_request(&first, first_scope, &request)
                .expect("first internal request");
        assert_eq!(
            first_internal.request_id(),
            derive_consumer_fenced_transition_request(&first, successor_scope, &request)
                .expect("successor internal request")
                .request_id(),
            "an authorized successor scope must recover the same receipt"
        );
        assert_ne!(
            first_internal.request_id(),
            derive_consumer_fenced_transition_request(&second, first_scope, &request)
                .expect("second internal request")
                .request_id(),
            "different authenticated consumers must not share a receipt domain"
        );
        let changed_body = FencedTransitionRequest::new(
            request.request_id(),
            request.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("changed transition body");
        assert_eq!(
            first_internal.request_id(),
            derive_consumer_fenced_transition_request(&first, first_scope, &changed_body)
                .expect("changed-body internal request")
                .request_id(),
            "the receipt ledger, not the derivation, must bind conflicting bodies"
        );
    }

    #[test]
    fn fenced_transition_requires_matching_outer_and_nested_identity() {
        let request = transition(0x44);
        let consumer = SessionConsumerRequest::new(
            scope(2, 1),
            SessionConsumerRequestId::from_bytes([0x45; 16]),
            SessionConsumerOperation::FencedTransition {
                request: Box::new(request),
            },
        );
        assert_eq!(
            consumer.validate(),
            Err(SessionConsumerRejection::MalformedRequest)
        );
    }

    #[test]
    fn fenced_transition_status_is_safe_and_preserves_terminal_states() {
        assert_eq!(
            SessionConsumerFencedTransitionStatus::from(FencedTransitionStatus::Expired),
            SessionConsumerFencedTransitionStatus::Expired
        );
        assert_eq!(
            SessionConsumerFencedTransitionStatus::from(FencedTransitionStatus::HistoryFull),
            SessionConsumerFencedTransitionStatus::HistoryFull
        );
        assert_eq!(
            SessionConsumerFencedTransitionError::from(
                StoreError::FencedTransitionStorageExhausted
            ),
            SessionConsumerFencedTransitionError::StorageExhausted,
        );
    }
}
