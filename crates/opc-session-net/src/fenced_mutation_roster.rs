//! Net-owned protected-roster client runtime.
//!
//! The persistent consumer module owns construction of this runtime from its
//! exact revision-five authenticated state.  Nothing in this module exposes a
//! generic transport or caller-selected consensus authority.
//!
//! ```compile_fail
//! use opc_session_net::ProtectedRosterTransport;
//!
//! // No downstream-implementable roster transport or generic compose function
//! // is exported. Construction starts at PersistentSessionConsumerClient.
//! let _ = core::any::type_name::<ProtectedRosterTransport>();
//! ```
//!
//! ```compile_fail
//! use opc_session_net::{FencedMutationRosterClient, SessionConsumerRosterAdmissionCapsule};
//!
//! // Raw roster capsules and direct roster execution are not net public API.
//! let _ = (FencedMutationRosterClient::new, SessionConsumerRosterAdmissionCapsule::new);
//! ```

mod canonical;
mod client;
mod diagnostics;
mod publication;
mod runtime;
mod scheduler;
pub(crate) mod transport;

use sha2::{Digest, Sha256};

const PROTECTED_ROSTER_CONSUMER_SCOPE_DOMAIN: &[u8] =
    b"openpacketcore/protected-roster/consumer-scope/v1\0";

/// Derive the one protected-roster authority scope for an authenticated
/// consensus configuration. This remains crate-private: public attestor
/// construction never accepts a caller-selected scope digest.
pub(crate) fn protected_roster_scope_from_consensus_identity(
    identity: crate::ConsensusIdentity,
) -> canonical::Scope {
    let mut hasher = Sha256::new();
    hasher.update(PROTECTED_ROSTER_CONSUMER_SCOPE_DOMAIN);
    hasher.update(identity.cluster_id().as_bytes());
    hasher.update(identity.configuration_id().as_bytes());
    hasher.update(identity.configuration_epoch().get().to_be_bytes());
    canonical::Scope::from_digest(hasher.finalize().into())
}

/// Topology-provisioned public trust root for executor terminal attestations.
///
/// This is fixed startup configuration. It contains no root private-key or
/// consensus capability, and terminal commands cannot select it.
#[derive(Clone)]
pub struct FencedMutationRosterAttestationTrustRootV1 {
    inner: opc_session_store::fenced_mutation_roster::RosterAttestationTrustRootV1,
}

impl FencedMutationRosterAttestationTrustRootV1 {
    /// Build one fixed topology root from its public identifier and compressed
    /// P-256 verification key.
    pub fn new(
        root_id: [u8; 32],
        public_key: [u8; 33],
    ) -> Result<Self, FencedMutationRosterExecutorError> {
        opc_session_store::fenced_mutation_roster::RosterAttestationTrustRootV1::new(
            root_id, public_key,
        )
        .map(|inner| Self { inner })
        .map_err(|_| runtime::ExecutorError::AttestationUnavailable)
    }

    pub(crate) fn as_store(
        &self,
    ) -> opc_session_store::fenced_mutation_roster::RosterAttestationTrustRootV1 {
        self.inner.clone()
    }

    #[cfg(test)]
    pub(crate) fn from_store(
        inner: opc_session_store::fenced_mutation_roster::RosterAttestationTrustRootV1,
    ) -> Self {
        Self { inner }
    }
}

/// Opaque root-signed Executor certificate fixed at startup.
///
/// Its construction fixes the leaf role to Executor. The executor verifies
/// the root signature and exact protected-roster scope before accepting it for
/// a terminal; callers cannot select a different certificate role or access
/// store certificate internals.
///
/// ```compile_fail
/// use opc_session_net::RosterAttestationCertificateRoleV1;
///
/// // Certificate roles are storage-internal. The net constructor always
/// // binds Executor and intentionally exposes no role selector.
/// let _ = RosterAttestationCertificateRoleV1::Executor;
/// ```
#[derive(Clone)]
pub struct FencedMutationRosterExecutorCertificatePartsV1 {
    inner: opc_session_store::fenced_mutation_roster::RosterAttestationLeafCertificatePartsV1,
}

impl FencedMutationRosterExecutorCertificatePartsV1 {
    /// Return the exact root-signing digest for public Executor certificate
    /// material. The protected-roster scope is derived internally from the
    /// supplied configuration identity. A topology authority signs this digest
    /// out of band, then the resulting signature is supplied to [`Self::new`].
    /// This helper exposes no root private key or generic roster signing
    /// capability.
    #[allow(clippy::too_many_arguments)]
    pub fn signing_digest(
        root_id: [u8; 32],
        configuration_identity: crate::ConsensusIdentity,
        subject_identity_commitment: [u8; 32],
        leaf_epoch: u64,
        key_id: [u8; 32],
        not_before: crate::Timestamp,
        not_after: crate::Timestamp,
        public_key: [u8; 33],
    ) -> Result<[u8; 32], FencedMutationRosterExecutorError> {
        opc_session_store::fenced_mutation_roster::RosterAttestationLeafCertificateV1::signing_digest(
            &Self::store_parts(
                root_id,
                configuration_identity,
                subject_identity_commitment,
                leaf_epoch,
                key_id,
                not_before,
                not_after,
                public_key,
                [0; 64],
            ),
        )
        .map_err(|_| runtime::ExecutorError::AttestationUnavailable)
    }

    /// Bind an already root-signed Executor certificate from public topology
    /// material. Its scope is derived from `configuration_identity`; callers
    /// cannot supply a raw scope. Invalid keys and validity windows fail
    /// closed here; the adapter verifies the root signature, and the executor
    /// verifies exact roster scope when it freezes this startup attestor for a
    /// registration.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root_id: [u8; 32],
        configuration_identity: crate::ConsensusIdentity,
        subject_identity_commitment: [u8; 32],
        leaf_epoch: u64,
        key_id: [u8; 32],
        not_before: crate::Timestamp,
        not_after: crate::Timestamp,
        public_key: [u8; 33],
        root_signature: [u8; 64],
    ) -> Result<Self, FencedMutationRosterExecutorError> {
        let inner = Self::store_parts(
            root_id,
            configuration_identity,
            subject_identity_commitment,
            leaf_epoch,
            key_id,
            not_before,
            not_after,
            public_key,
            root_signature,
        );
        // The store canonicalizer checks the fixed Executor role, compressed
        // key encoding, and nonempty validity range without exposing its
        // certificate object to the net caller.
        opc_session_store::fenced_mutation_roster::RosterAttestationLeafCertificateV1::signing_digest(
            &inner,
        )
        .map_err(|_| runtime::ExecutorError::AttestationUnavailable)?;
        Ok(Self { inner })
    }

    #[allow(clippy::too_many_arguments)]
    fn store_parts(
        root_id: [u8; 32],
        configuration_identity: crate::ConsensusIdentity,
        subject_identity_commitment: [u8; 32],
        leaf_epoch: u64,
        key_id: [u8; 32],
        not_before: crate::Timestamp,
        not_after: crate::Timestamp,
        public_key: [u8; 33],
        root_signature: [u8; 64],
    ) -> opc_session_store::fenced_mutation_roster::RosterAttestationLeafCertificatePartsV1 {
        opc_session_store::fenced_mutation_roster::RosterAttestationLeafCertificatePartsV1 {
            root_id,
            role: opc_session_store::fenced_mutation_roster::RosterAttestationCertificateRoleV1::Executor,
            configuration_identity,
            scope: protected_roster_scope_from_consensus_identity(configuration_identity).digest(),
            subject_identity_commitment,
            leaf_epoch,
            key_id,
            not_before,
            not_after,
            public_key,
            root_signature,
        }
    }

    pub(crate) fn as_store(
        &self,
    ) -> opc_session_store::fenced_mutation_roster::RosterAttestationLeafCertificatePartsV1 {
        self.inner.clone()
    }

    #[cfg(test)]
    pub(crate) fn from_store(
        inner: opc_session_store::fenced_mutation_roster::RosterAttestationLeafCertificatePartsV1,
    ) -> Self {
        Self { inner }
    }
}

/// Opaque borrowed V1 terminal-member signing view constructed by the SDK.
///
/// It exposes only the prehash a local HSM/KMS needs to sign. Downstream code
/// cannot construct, retain, or convert this view into a terminal proof or an
/// authority capability; the executor and durable backend reconstruct and
/// compare every binding before accepting a returned signature.
pub struct FencedMutationRosterTerminalAttestationSigningInputV1<'a> {
    inner: &'a opc_session_store::fenced_mutation_roster::RosterTerminalAttestationSigningInputV1,
}

impl FencedMutationRosterTerminalAttestationSigningInputV1<'_> {
    /// Return the exact P-256 prehash for this SDK-constructed member.
    pub fn signing_digest(&self) -> Result<[u8; 32], FencedMutationRosterExecutorError> {
        self.inner
            .digest()
            .map_err(|_| runtime::ExecutorError::AttestationUnavailable)
    }
}

impl<'a> FencedMutationRosterTerminalAttestationSigningInputV1<'a> {
    pub(crate) const fn from_store(
        inner: &'a opc_session_store::fenced_mutation_roster::RosterTerminalAttestationSigningInputV1,
    ) -> Self {
        Self { inner }
    }
}

/// Opaque borrowed V2 compact terminal-member signing view constructed by the
/// SDK. It exposes only the P-256 prehash required by a local signer.
pub struct FencedMutationRosterCompactTerminalMemberSigningInputV2<'a> {
    inner: &'a opc_session_store::fenced_mutation_roster::RosterCompactTerminalMemberSigningInputV2,
}

impl FencedMutationRosterCompactTerminalMemberSigningInputV2<'_> {
    /// Return the exact P-256 prehash for this SDK-constructed compact member.
    pub fn signing_digest(&self) -> Result<[u8; 32], FencedMutationRosterExecutorError> {
        self.inner
            .digest()
            .map_err(|_| runtime::ExecutorError::AttestationUnavailable)
    }
}

impl<'a> FencedMutationRosterCompactTerminalMemberSigningInputV2<'a> {
    pub(crate) const fn from_store(
        inner: &'a opc_session_store::fenced_mutation_roster::RosterCompactTerminalMemberSigningInputV2,
    ) -> Self {
        Self { inner }
    }
}

/// Return the exact P-256 prehash an executor leaf signs for one V1 terminal
/// member input.
///
/// This does not create a terminal proof or confer authority. The executor and
/// durable backend accept a signature only after independently reconstructing
/// and checking the same input from retained protected-roster state.
pub fn fenced_mutation_roster_terminal_attestation_signing_digest_v1(
    input: &FencedMutationRosterTerminalAttestationSigningInputV1<'_>,
) -> Result<[u8; 32], FencedMutationRosterExecutorError> {
    input.signing_digest()
}

/// Return the exact P-256 prehash an executor leaf signs for one V2 compact
/// terminal member input.
///
/// This does not create a terminal proof or confer authority. The executor and
/// durable backend accept a signature only after independently reconstructing
/// and checking the same input from retained protected-roster state.
pub fn fenced_mutation_roster_compact_terminal_member_signing_digest_v2(
    input: &FencedMutationRosterCompactTerminalMemberSigningInputV2<'_>,
) -> Result<[u8; 32], FencedMutationRosterExecutorError> {
    input.signing_digest()
}

pub use canonical::{
    AbsentAdmissionProposal as FencedMutationRosterAbsentAdmissionProposal,
    AdmissionProposal as FencedMutationRosterAdmissionProposal,
    EstablishedMutation as FencedMutationRosterEstablishedMutation,
    EstablishedPublicationCall as FencedMutationRosterEstablishedPublicationCall,
    Member as FencedMutationRosterMember, MemberAdoption as FencedMutationRosterMemberAdoption,
    MemberCall as FencedMutationRosterMemberCall,
    MemberDisposition as FencedMutationRosterMemberDisposition,
    MemberOperationId as FencedMutationRosterMemberOperationId, Phase as FencedMutationRosterPhase,
    Profile as FencedMutationRosterProfile,
    PublicationEvidence as FencedMutationRosterPublicationEvidence,
    PublicationId as FencedMutationRosterPublicationId,
    PublicationProviderOutcome as FencedMutationRosterPublicationProviderOutcome,
    RosterId as FencedMutationRosterId,
};
pub use canonical::{
    EstablishedPublicationProvider as FencedMutationRosterEstablishedPublicationProvider,
    MemberProvider as FencedMutationRosterMemberProvider,
    ProviderCallOutcome as FencedMutationRosterProviderCallOutcome,
    ProviderReceiptCapsule as FencedMutationRosterProviderReceiptCapsule,
    ProviderReceiptChallenge as FencedMutationRosterProviderReceiptChallenge,
};
pub use canonical::{
    CONSUMER_ALPN as FENCED_MUTATION_ROSTER_CONSUMER_ALPN,
    CONSUMER_ALPN_V2 as FENCED_MUTATION_ROSTER_CONSUMER_ALPN_V2,
    CONSUMER_REVISION as FENCED_MUTATION_ROSTER_CONSUMER_REVISION,
    CONSUMER_REVISION_V2 as FENCED_MUTATION_ROSTER_CONSUMER_REVISION_V2,
    FRESH_ROSTER_MEMBERS as FENCED_MUTATION_ROSTER_FRESH_MEMBERS,
    INITIAL_GENERATION as FENCED_MUTATION_ROSTER_INITIAL_GENERATION,
    MAX_CHECKPOINT_BYTES as FENCED_MUTATION_ROSTER_MAX_CHECKPOINT_BYTES,
    MAX_DESCRIPTOR_BYTES as FENCED_MUTATION_ROSTER_MAX_DESCRIPTOR_BYTES,
    MAX_HISTORY_EPOCH as FENCED_MUTATION_ROSTER_MAX_HISTORY_EPOCH,
    MAX_LIVE_ROSTERS as FENCED_MUTATION_ROSTER_MAX_LIVE_ROSTERS,
    MAX_MEMBERS as FENCED_MUTATION_ROSTER_MAX_MEMBERS,
    MAX_PLAN_BYTES as FENCED_MUTATION_ROSTER_MAX_PLAN_BYTES,
    MAX_RESERVED_AND_RETAINED as FENCED_MUTATION_ROSTER_MAX_RESERVED_AND_RETAINED,
    MAX_RESULT_BYTES as FENCED_MUTATION_ROSTER_MAX_RESULT_BYTES,
    MAX_STATUS_BYTES as FENCED_MUTATION_ROSTER_MAX_STATUS_BYTES,
    MEMBER_OPERATION_ID_BYTES as FENCED_MUTATION_ROSTER_MEMBER_OPERATION_ID_BYTES,
    OPERATIONAL_TARGET as FENCED_MUTATION_ROSTER_OPERATIONAL_TARGET,
    ROSTER_ID_BYTES as FENCED_MUTATION_ROSTER_ID_BYTES,
    SCHEMA_V1 as FENCED_MUTATION_ROSTER_SCHEMA_V1, SCHEMA_V2 as FENCED_MUTATION_ROSTER_SCHEMA_V2,
};
pub use client::{
    AbortedTerminal as FencedMutationRosterAbortedTerminal,
    ActiveRoster as FencedMutationRosterActive,
    AdmissionInput as FencedMutationRosterAdmissionInput,
    AdmissionOutcome as FencedMutationRosterAdmissionOutcome,
    AdmissionUnknown as FencedMutationRosterAdmissionUnknown,
    ClientError as FencedMutationRosterClientError,
    CompleteProofSet as FencedMutationRosterCompleteProofSet,
    EstablishedPublication as FencedMutationRosterEstablishedPublication,
    EstablishedTerminal as FencedMutationRosterEstablishedTerminal,
    ExecuteOutcome as FencedMutationRosterExecuteOutcome, FencedMutationRosterClient,
    MemberOrdinal as FencedMutationRosterMemberOrdinal,
    MemberPrepareOutcome as FencedMutationRosterMemberPrepareOutcome,
    MemberProof as FencedMutationRosterMemberProof,
    MemberRecoveryOutcome as FencedMutationRosterMemberRecoveryOutcome,
    MemberRecoveryStatus as FencedMutationRosterMemberRecoveryStatus,
    PreparedRosterTerminal as FencedMutationRosterPreparedTerminal,
    ReadyMember as FencedMutationRosterReadyMember,
    RecoverableMember as FencedMutationRosterRecoverableMember,
    RecoveredRoster as FencedMutationRosterRecovered,
    RecoveryInput as FencedMutationRosterRecoveryInput,
    RecoveryOutcome as FencedMutationRosterRecoveryOutcome,
    TerminalReceipt as FencedMutationRosterTerminalReceipt,
    TerminalRoster as FencedMutationRosterTerminal,
    TerminalStatus as FencedMutationRosterTerminalStatus,
    TerminalizationOutcome as FencedMutationRosterTerminalizationOutcome,
};
pub use diagnostics::FencedMutationRosterDiagnostics;
pub use publication::PublicationAdapterError as FencedMutationRosterPublicationError;
pub use runtime::{
    ExecutorError as FencedMutationRosterExecutorError, FencedMutationRosterExecutorAttestor,
    FencedMutationRosterExecutorAttestorAdapter, FencedMutationRosterExecutorTerminalSigner,
};
pub use transport::{
    FencedMutationRosterProviderAdapter, FencedMutationRosterProviderAdapterDiagnostics,
    ProtectedRosterTransportError, MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES, MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
};
