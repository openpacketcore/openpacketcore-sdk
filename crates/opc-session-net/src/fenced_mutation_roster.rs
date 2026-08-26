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

pub use canonical::{
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
    CONSUMER_REVISION as FENCED_MUTATION_ROSTER_CONSUMER_REVISION,
    FRESH_ROSTER_MEMBERS as FENCED_MUTATION_ROSTER_FRESH_MEMBERS,
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
    ROSTER_ID_BYTES as FENCED_MUTATION_ROSTER_ID_BYTES,
    SCHEMA_V1 as FENCED_MUTATION_ROSTER_SCHEMA_V1,
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
#[doc(hidden)]
pub use runtime::{
    ExecutorError as FencedMutationRosterExecutorError, FencedMutationRosterExecutorAttestor,
};
pub use transport::{
    FencedMutationRosterProviderAdapter, FencedMutationRosterProviderAdapterDiagnostics,
    ProtectedRosterTransportError, MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
    MAX_PROTECTED_ROSTER_PORT_ENVELOPE_OVERHEAD_BYTES, MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
};
