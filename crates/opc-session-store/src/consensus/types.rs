//! Session state-machine commands built on the shared consensus substrate.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::backend::{CompareAndSet, CompareAndSetResult};
use crate::error::StoreError;
use crate::fenced_mutation_roster::{
    Admission, RequestBindingKey, RequestId as RosterRequestId, RosterCompactAdmissionProvenanceV2,
    RosterCompactTerminalEvidenceV2, RosterExecutorProofBundleV1, RosterIngressAttestationV1,
    TerminalConflictTombstone, TerminalRecord, MAX_ADMISSION_CODEC_BYTES,
    MAX_COMMITTED_TERMINAL_CODEC_BYTES, MAX_EXECUTOR_PROOF_BUNDLE_BYTES,
    MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES, MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES,
    MAX_ROSTER_INGRESS_ATTESTATION_BYTES, MAX_TERMINAL_CODEC_BYTES, MAX_TOMBSTONE_CODEC_BYTES,
};
use crate::fenced_mutation_roster_executor::{
    AuthorityBinding, AuthorityLeaseMetadata, BackendRegistration, CommittedTerminal,
};
use crate::fenced_transition::{
    FencedTransitionOutcome, FencedTransitionRequest, FencedTransitionV2HistoryEpoch,
    FencedTransitionV2Request,
};
use crate::lease::LeaseGuard;
use crate::model::{FenceToken, Generation, OwnerId, SessionKey};
use crate::record::StoredSessionRecord;

pub use opc_consensus::{
    ConsensusClusterId as SessionConsensusClusterId,
    ConsensusConfigurationEpoch as SessionConsensusConfigurationEpoch,
    ConsensusConfigurationId as SessionConsensusConfigurationId,
    ConsensusEntryDigest as SessionConsensusEntryDigest,
    ConsensusIdentity as SessionConsensusIdentity,
    ConsensusIdentityError as SessionConsensusIdentityError,
    ConsensusNodeId as SessionConsensusNodeId, ConsensusRequestId as SessionConsensusRequestId,
};

/// Current durable command and consensus-RPC schema.
pub const SESSION_CONSENSUS_SCHEMA_VERSION: u16 = opc_consensus::CONSENSUS_SCHEMA_VERSION;

/// Maximum accepted byte length of a caller-supplied cluster name.
pub const SESSION_CONSENSUS_CLUSTER_ID_MAX_BYTES: usize =
    opc_consensus::CONSENSUS_CLUSTER_ID_MAX_BYTES;

const COMMAND_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/command/v1\0";
const COMMAND_V2_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/command/v2-fixed\0";
const COMMAND_V2_DIGEST_MAGIC: &[u8] = b"OPC-SC-V2-APPLIED\0";
/// Fixed V2 applied-command digest encoding revision.
///
/// This applies only to commands which carry a V2 intent (directly or in the
/// one permitted [`SessionMutationIntent::Authorized`] envelope). Older
/// commands retain their byte-for-byte JSON digest encoding.
pub const SESSION_CONSENSUS_V2_APPLIED_DIGEST_ENCODING_VERSION: u16 = 2;
/// Frozen descriptor of V2's fixed applied-command digest input.
///
/// The V2 fenced-transition profile must bind this descriptor: changing any
/// tag, width, field order, or domain changes the replicated digest chain.
pub const SESSION_CONSENSUS_V2_APPLIED_DIGEST_SCHEMA_DESCRIPTOR: &str = concat!(
    "domain=openpacketcore/session-consensus/command/v2-fixed\\0;",
    "magic=OPC-SC-V2-APPLIED\\0;revision:u16be=2;",
    "prefix=sequence:u64be|previous-digest:bytes32|effective-time:timestamp;",
    "command=schema:u16be|storage-identity:identity|outer-id:bytes16|logical-time:timestamp|intent;",
    "timestamp=unix-secs:i64be|nanos:u32be;identity=cluster:bytes32|configuration:bytes32|epoch:u64be;",
    "intent=fenced-v2(tag=1,id:bytes56)|activate-v2(tag=2,id:bytes56,scope:identity,voters:bytes32,profile:bytes32)|",
    "maintain-v2(tag=3,generation:u64be,active:option-tag-u8+epoch:u64be,retired:u64be,bound:u64be)|",
    "authorized(tag=4,origin:u64be,authority:identity,mutation:intent)|",
    "fenced-v2-batch(tag=5,count:u16be,items:ordered-full-id:bytes56)"
);
/// Frozen Postcard command-wire shape for V2 replicated intents.
///
/// Normal Openraft payloads and peer forwarding retain the generic bounded
/// Postcard codec. These appended intent discriminants are therefore profile
/// material in addition to the fixed applied-digest encoding.
pub const SESSION_CONSENSUS_V2_COMMAND_WIRE_SCHEMA_DESCRIPTOR: &str = concat!(
    "wire-profile=1;raft-rpc-codec=postcard;durable-log-codec=serde-json;",
    "command-fields=schema-version,identity,request-id,logical-time,intent;",
    "intent-discriminants=authorized:15|fenced-v1:16|activate-v1:17|",
    "fenced-v2:18|activate-v2:19|maintain-v2:20|fenced-v2-batch:21;",
    "postcard=derive-serde,struct-fields-declaration-order,enum-tags=varint;",
    "json=derive-serde,struct-field-names-declaration-order,enum-names-exact;",
    "fenced-v2=box(request-fields=request-id:epoch:u64,nonce:bytes16,commitment:bytes32|lease|mutation);",
    "lease-discriminants=acquire:0(key,owner,fence,ttl)|renew:1(guard,ttl);",
    "mutation-discriminants=create:0(record)|update:1(generation,record)|delete:2(generation)|refresh-ttl:3(generation,ttl);",
    "activate-v2=box(request)|scope:identity|voters:bytes32|profile:bytes32;",
    "maintain-v2=generation:u64|active:option(epoch:u64)|retired:u64|bound:u64;",
    "fenced-v2-batch=vec(request-fields=request-id:epoch:u64,nonce:bytes16,commitment:bytes32|lease|mutation),",
    "count=1..=256,ordered,unique-full-ids,single-history-epoch,postcard-bytes<=1048576,",
    "outer-id=sha256(domain=openpacketcore/session-consensus/fenced-transition/v2/batch/outer-id/v1\\0,",
    "count:u16be,ordered-full-ids:bytes56)[0..16];",
    "authorized=origin:node-id|authority:identity|box(intent)"
);
const FENCED_TRANSITION_VOTER_SET_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/fenced-transition-voter-set/v1\0";
/// Domain-separated immutable protected-roster profile certificate binding.
///
/// This deliberately wraps the exact V1 voter scope rather than changing the
/// certificate table shape: a V1-only activation can therefore never be
/// mistaken for unanimous support of the frozen protected-roster profile.
const PROTECTED_ROSTER_PROFILE_VOTER_SET_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/protected-roster-profile-voter-set/v1\0";
const FENCED_TRANSITION_V2_BATCH_OUTER_REQUEST_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/fenced-transition/v2/batch/outer-id/v1\0";

/// Maximum ordered V2 transitions admitted by one replicated batch command.
pub const MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS: usize = 256;

/// Maximum fully Postcard-encoded V2 batch request bytes.
///
/// This leaves one MiB of deterministic command-envelope headroom beneath
/// the existing two MiB consensus RPC ceiling.
pub const MAX_SESSION_FENCED_TRANSITION_V2_BATCH_REQUEST_BYTES: usize = 1024 * 1024;

/// Maximum fully Postcard-encoded V2 batch outcome bytes.
///
/// The same fixed cap keeps a complete correlated outcome vector within the
/// existing consensus response and consumer frame profiles.
pub const MAX_SESSION_FENCED_TRANSITION_V2_BATCH_RESPONSE_BYTES: usize = 1024 * 1024;

const ROSTER_REGISTRATION_HANDLE_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/roster-registration-handle/v1\0";
const ROSTER_ADMISSION_SLOT_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/roster-admission-slot/v2\0";
const ROSTER_CONSENSUS_REQUEST_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/roster-request-id/v1\0";
const ROSTER_ADMISSION_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/roster-admission-payload/v1\0";
const ROSTER_TERMINAL_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/roster-terminal-payload/v1\0";
const ROSTER_COMMAND_ATTEMPT_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/roster-command-attempt/v1\0";
const ROSTER_APPLIED_DIGEST_DOMAIN: &[u8] = b"openpacketcore/session-consensus/roster-applied/v1\0";
const ROSTER_APPLIED_DIGEST_MAGIC: &[u8] = b"OPC-SC-ROSTER-APPLIED\0";
/// Fixed roster applied-command digest encoding revision.
///
/// This is deliberately independent from the fenced-transition V2 encoding:
/// roster commands retain their own wire schema and durable body semantics.
pub const SESSION_CONSENSUS_ROSTER_APPLIED_DIGEST_ENCODING_VERSION: u16 = 1;
const ROSTER_COMMAND_REJECTED: &str = "roster consensus command rejected";

/// Produce the canonical, non-describing binding of one exact voter scope.
///
/// The durable activation certificate stores this digest rather than a second
/// copy of membership descriptors.  The current scope remains authoritative
/// for the actual members, while this fixed-width value prevents a certificate
/// from being reused after a configuration or voter-set change.
pub(crate) fn fenced_transition_voter_set_digest(
    identity: SessionConsensusIdentity,
    voters: &BTreeSet<SessionConsensusNodeId>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FENCED_TRANSITION_VOTER_SET_DIGEST_DOMAIN);
    hasher.update(identity.cluster_id().as_bytes());
    hasher.update(identity.configuration_id().as_bytes());
    hasher.update(identity.configuration_epoch().get().to_be_bytes());
    for voter in voters {
        hasher.update(voter.get().to_be_bytes());
    }
    hasher.finalize().into()
}

/// Bind the exact voter scope to the immutable protected-roster profile.
///
/// The profile itself is static SDK configuration, so retaining this digest in
/// the existing activation certificate is sufficient for deterministic
/// follower apply, snapshots, and restart without a second mutable profile
/// record.
pub(crate) fn protected_roster_profile_voter_set_digest(
    identity: SessionConsensusIdentity,
    voters: &BTreeSet<SessionConsensusNodeId>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROTECTED_ROSTER_PROFILE_VOTER_SET_DIGEST_DOMAIN);
    hasher.update(fenced_transition_voter_set_digest(identity, voters));
    hasher.update(crate::fenced_mutation_roster::profile_digest());
    hasher.finalize().into()
}

/// Redacted fixed-width binding of one topology member's admitted identities.
///
/// The SDK persists only domain-separated fingerprints. Raw endpoints, TLS
/// identities, and backing-store identities never enter transition evidence
/// or diagnostic rendering.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionTopologyMemberBinding {
    descriptor: [u8; 32],
    endpoint: [u8; 32],
    tls_identity: [u8; 32],
    backing_identity: [u8; 32],
}

impl SessionTopologyMemberBinding {
    pub(crate) const fn new(
        descriptor: [u8; 32],
        endpoint: [u8; 32],
        tls_identity: [u8; 32],
        backing_identity: [u8; 32],
    ) -> Self {
        Self {
            descriptor,
            endpoint,
            tls_identity,
            backing_identity,
        }
    }

    pub(crate) const fn descriptor(self) -> [u8; 32] {
        self.descriptor
    }

    pub(crate) const fn endpoint(self) -> [u8; 32] {
        self.endpoint
    }

    pub(crate) const fn tls_identity(self) -> [u8; 32] {
        self.tls_identity
    }

    pub(crate) const fn backing_identity(self) -> [u8; 32] {
        self.backing_identity
    }
}

impl fmt::Debug for SessionTopologyMemberBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionTopologyMemberBinding(<redacted>)")
    }
}

/// Bounded opaque canonical roster bytes retained only in private consensus
/// commands. Its visitor rejects oversized sequences before retaining them.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct BoundedRosterCapsule<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> BoundedRosterCapsule<MAX> {
    fn new(bytes: Vec<u8>) -> Result<Self, StoreError> {
        if bytes.len() > MAX {
            return Err(StoreError::PayloadTooLarge {
                actual: bytes.len(),
                max: MAX,
            });
        }
        Ok(Self(bytes))
    }

    fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<const MAX: usize> Serialize for BoundedRosterCapsule<MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for BoundedRosterCapsule<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CapsuleVisitor<const MAX: usize>;

        impl<'de, const MAX: usize> Visitor<'de> for CapsuleVisitor<MAX> {
            type Value = BoundedRosterCapsule<MAX>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded opaque roster capsule")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > MAX {
                    return Err(E::custom("bounded roster capsule exceeds limit"));
                }
                Ok(BoundedRosterCapsule(value.to_vec()))
            }

            fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_bytes(value)
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value.len() > MAX {
                    return Err(E::custom("bounded roster capsule exceeds limit"));
                }
                Ok(BoundedRosterCapsule(value))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                if sequence.size_hint().is_some_and(|length| length > MAX) {
                    return Err(serde::de::Error::custom(
                        "bounded roster capsule exceeds limit",
                    ));
                }
                let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == MAX {
                        return Err(serde::de::Error::custom(
                            "bounded roster capsule exceeds limit",
                        ));
                    }
                    bytes.push(byte);
                }
                Ok(BoundedRosterCapsule(bytes))
            }
        }

        deserializer.deserialize_bytes(CapsuleVisitor::<MAX>)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ConsensusRosterAuthorityWire {
    scope: [u8; 32],
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    credential_id: u64,
    generation: Generation,
    acquired_at: opc_types::Timestamp,
    expires_at: opc_types::Timestamp,
}

impl From<&AuthorityBinding> for ConsensusRosterAuthorityWire {
    fn from(value: &AuthorityBinding) -> Self {
        Self {
            scope: value.scope().digest(),
            key: value.key().clone(),
            owner: value.owner().clone(),
            fence: value.fence(),
            credential_id: value.credential_id(),
            generation: value.generation(),
            acquired_at: value.acquired_at(),
            expires_at: value.expires_at(),
        }
    }
}

impl ConsensusRosterAuthorityWire {
    fn into_authority(self) -> Result<AuthorityBinding, StoreError> {
        AuthorityBinding::from_consensus_parts(
            self.scope,
            self.key,
            self.owner,
            self.fence,
            AuthorityLeaseMetadata::new(
                self.credential_id,
                self.generation,
                self.acquired_at,
                self.expires_at,
            ),
        )
        .map_err(|_| roster_command_rejected())
    }
}

fn roster_command_rejected() -> StoreError {
    StoreError::InvalidKey(ROSTER_COMMAND_REJECTED.into())
}

pub(crate) fn roster_registration_handle(binding: RequestBindingKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_REGISTRATION_HANDLE_DOMAIN);
    hasher.update(binding.to_bytes());
    let mut handle: [u8; 32] = hasher.finalize().into();
    if handle == [0; 32] {
        handle[0] = 1;
    }
    handle
}

fn roster_admission_slot(admission: &Admission) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_ADMISSION_SLOT_DOMAIN);
    hasher.update(admission.scope().digest());
    let key = admission.key().canonical_digest_input();
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key);
    hasher.update(admission.roster_id().as_bytes());
    hasher.finalize().into()
}

fn roster_consensus_request_id(slot: [u8; 32]) -> SessionConsensusRequestId {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_CONSENSUS_REQUEST_ID_DOMAIN);
    hasher.update(slot);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_id = [0; 16];
    request_id.copy_from_slice(&digest[..16]);
    if request_id == [0; 16] {
        request_id[0] = 1;
    }
    SessionConsensusRequestId::from_bytes(request_id)
}

/// Non-wire commitments computed only after a roster command has been
/// canonicalized and structurally authenticated.  Keeping them on the
/// in-memory command avoids re-encoding megabyte-scale bodies every time the
/// state machine binds an outcome or extends its applied-digest chain.
///
/// Both values intentionally retain their established domains and byte
/// inputs.  A snapshot or follower reconstructs this cache through the same
/// validating deserializer; it is never serialized or trusted from the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ConsensusRosterCommandDigestCache {
    immutable_payload_digest: [u8; 32],
    exact_attempt_digest: [u8; 32],
}

fn roster_authority_canonical_bytes(authority: &AuthorityBinding) -> Result<Vec<u8>, StoreError> {
    postcard::to_allocvec(&ConsensusRosterAuthorityWire::from(authority))
        .map_err(|_| roster_command_rejected())
}

fn roster_admission_immutable_payload_digest(admission: &[u8], authority: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_ADMISSION_PAYLOAD_DIGEST_DOMAIN);
    hasher.update((admission.len() as u64).to_be_bytes());
    hasher.update(admission);
    hasher.update((authority.len() as u64).to_be_bytes());
    hasher.update(authority);
    hasher.finalize().into()
}

fn roster_terminal_immutable_payload_digest(
    binding: RequestBindingKey,
    registration_handle: [u8; 32],
    registration_request_id: RosterRequestId,
    registration_terminal_slot: [u8; 32],
    record: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_TERMINAL_PAYLOAD_DIGEST_DOMAIN);
    hasher.update(binding.to_bytes());
    hasher.update(registration_handle);
    hasher.update(registration_request_id.to_bytes());
    hasher.update(registration_terminal_slot);
    hasher.update((record.len() as u64).to_be_bytes());
    hasher.update(record);
    hasher.finalize().into()
}

/// Hash one exact Postcard byte string without allocating a second copy of a
/// large capsule.  `BoundedRosterCapsule` serializes as Postcard `bytes`,
/// whose length prefix is this unsigned LEB128 form.
fn roster_update_postcard_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    let mut length = bytes.len();
    loop {
        let mut byte = length.to_le_bytes()[0] & 0x7f;
        length >>= 7;
        if length != 0 {
            byte |= 0x80;
        }
        hasher.update([byte]);
        if length == 0 {
            break;
        }
    }
    hasher.update(bytes);
}

fn roster_postcard_bytes_len(bytes: &[u8]) -> usize {
    let mut length = bytes.len();
    let mut prefix_len = 1;
    while length >= 128 {
        length >>= 7;
        prefix_len += 1;
    }
    prefix_len + bytes.len()
}

fn roster_command_attempt_hasher(operation_tag: u8, canonical_len: usize) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_COMMAND_ATTEMPT_DIGEST_DOMAIN);
    hasher.update([operation_tag]);
    hasher.update((canonical_len as u64).to_be_bytes());
    hasher
}

fn roster_admission_digest_cache(
    admission: &Admission,
    authority: &AuthorityBinding,
    ingress_request_id: [u8; 16],
    ingress_attestation: &[u8],
    admission_provenance: &[u8],
) -> Result<ConsensusRosterCommandDigestCache, StoreError> {
    let admission = admission
        .to_canonical_bytes()
        .map_err(|_| roster_command_rejected())?;
    let authority = roster_authority_canonical_bytes(authority)?;
    let canonical_len = roster_postcard_bytes_len(&admission)
        + authority.len()
        + ingress_request_id.len()
        + roster_postcard_bytes_len(ingress_attestation)
        + roster_postcard_bytes_len(admission_provenance);
    let mut exact_attempt = roster_command_attempt_hasher(1, canonical_len);
    roster_update_postcard_bytes(&mut exact_attempt, &admission);
    exact_attempt.update(&authority);
    exact_attempt.update(ingress_request_id);
    roster_update_postcard_bytes(&mut exact_attempt, ingress_attestation);
    roster_update_postcard_bytes(&mut exact_attempt, admission_provenance);
    Ok(ConsensusRosterCommandDigestCache {
        immutable_payload_digest: roster_admission_immutable_payload_digest(&admission, &authority),
        exact_attempt_digest: exact_attempt.finalize().into(),
    })
}

struct RosterTerminalDigestCacheInput<'a> {
    binding: RequestBindingKey,
    registration_handle: [u8; 32],
    registration_request_id: RosterRequestId,
    registration_terminal_slot: [u8; 32],
    authority: &'a AuthorityBinding,
    record: &'a [u8],
    proof_bundle: &'a [u8],
    terminal_evidence: &'a [u8],
    ingress_request_id: [u8; 16],
    ingress_attestation: &'a [u8],
}

fn roster_terminal_digest_cache(
    input: RosterTerminalDigestCacheInput<'_>,
) -> Result<ConsensusRosterCommandDigestCache, StoreError> {
    let RosterTerminalDigestCacheInput {
        binding,
        registration_handle,
        registration_request_id,
        registration_terminal_slot,
        authority,
        record,
        proof_bundle,
        terminal_evidence,
        ingress_request_id,
        ingress_attestation,
    } = input;
    let binding_encoded = postcard::to_allocvec(&binding).map_err(|_| roster_command_rejected())?;
    let registration_request_id_encoded =
        postcard::to_allocvec(&registration_request_id).map_err(|_| roster_command_rejected())?;
    let authority = roster_authority_canonical_bytes(authority)?;
    let canonical_len = binding_encoded.len()
        + registration_handle.len()
        + registration_request_id_encoded.len()
        + registration_terminal_slot.len()
        + authority.len()
        + roster_postcard_bytes_len(record)
        + roster_postcard_bytes_len(proof_bundle)
        + roster_postcard_bytes_len(terminal_evidence)
        + ingress_request_id.len()
        + roster_postcard_bytes_len(ingress_attestation);
    let mut exact_attempt = roster_command_attempt_hasher(2, canonical_len);
    exact_attempt.update(&binding_encoded);
    exact_attempt.update(registration_handle);
    exact_attempt.update(&registration_request_id_encoded);
    exact_attempt.update(registration_terminal_slot);
    exact_attempt.update(&authority);
    roster_update_postcard_bytes(&mut exact_attempt, record);
    roster_update_postcard_bytes(&mut exact_attempt, proof_bundle);
    roster_update_postcard_bytes(&mut exact_attempt, terminal_evidence);
    exact_attempt.update(ingress_request_id);
    roster_update_postcard_bytes(&mut exact_attempt, ingress_attestation);
    Ok(ConsensusRosterCommandDigestCache {
        immutable_payload_digest: roster_terminal_immutable_payload_digest(
            binding,
            registration_handle,
            registration_request_id,
            registration_terminal_slot,
            record,
        ),
        exact_attempt_digest: exact_attempt.finalize().into(),
    })
}

/// The sole replicated immutable roster-admission mutation.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct ConsensusRosterAdmissionCommand {
    admission: Admission,
    authority: AuthorityBinding,
    ingress_request_id: [u8; 16],
    ingress_attestation: BoundedRosterCapsule<MAX_ROSTER_INGRESS_ATTESTATION_BYTES>,
    admission_provenance: BoundedRosterCapsule<MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES>,
    digest_cache: ConsensusRosterCommandDigestCache,
}

impl ConsensusRosterAdmissionCommand {
    fn new_from_parts(
        admission: Admission,
        authority: AuthorityBinding,
        ingress_request_id: [u8; 16],
        ingress_attestation: BoundedRosterCapsule<MAX_ROSTER_INGRESS_ATTESTATION_BYTES>,
        admission_provenance: BoundedRosterCapsule<MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES>,
    ) -> Result<Self, StoreError> {
        if authority.scope() != admission.scope()
            || authority.key() != admission.key()
            || authority.owner() != admission.logical_owner()
            || authority.fence() != admission.admission_fence()
            || authority.generation() != admission.expected_generation()
        {
            return Err(roster_command_rejected());
        }
        let digest_cache = roster_admission_digest_cache(
            &admission,
            &authority,
            ingress_request_id,
            &ingress_attestation.0,
            &admission_provenance.0,
        )?;
        Ok(Self {
            admission,
            authority,
            ingress_request_id,
            ingress_attestation,
            admission_provenance,
            digest_cache,
        })
    }

    #[cfg(test)]
    pub(crate) fn new(
        admission: Admission,
        authority: AuthorityBinding,
    ) -> Result<Self, StoreError> {
        Self::new_from_parts(
            admission,
            authority,
            [0; 16],
            BoundedRosterCapsule::new(Vec::new())?,
            BoundedRosterCapsule::new(Vec::new())?,
        )
    }

    /// Construct the only production admission command form.  It carries the
    /// exact V1 ingress statement and its compact V2 root-verifiable
    /// provenance; a command without either is test-only and cannot be
    /// deserialized from the replicated wire.
    pub(crate) fn new_with_provenance_and_ingress_request_id(
        admission: Admission,
        authority: AuthorityBinding,
        ingress_request_id: [u8; 16],
        ingress_attestation: RosterIngressAttestationV1,
        admission_provenance: RosterCompactAdmissionProvenanceV2,
    ) -> Result<Self, StoreError> {
        if ingress_request_id == [0; 16] || ingress_attestation.request_id() != ingress_request_id {
            return Err(roster_command_rejected());
        }
        Self::new_from_parts(
            admission,
            authority,
            ingress_request_id,
            BoundedRosterCapsule::new(
                ingress_attestation
                    .canonical_bytes()
                    .map_err(|_| roster_command_rejected())?,
            )?,
            BoundedRosterCapsule::new(
                admission_provenance
                    .canonical_bytes()
                    .map_err(|_| roster_command_rejected())?,
            )?,
        )
    }

    pub(crate) fn admission(&self) -> &Admission {
        &self.admission
    }

    pub(crate) fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }

    pub(crate) fn ingress_attestation(&self) -> Result<RosterIngressAttestationV1, StoreError> {
        RosterIngressAttestationV1::decode_canonical(&self.ingress_attestation.0)
            .map_err(|_| roster_command_rejected())
    }

    /// Decode the exact compact admission provenance retained in this command.
    pub(crate) fn admission_provenance(
        &self,
    ) -> Result<RosterCompactAdmissionProvenanceV2, StoreError> {
        RosterCompactAdmissionProvenanceV2::decode_canonical(&self.admission_provenance.0)
            .map_err(|_| roster_command_rejected())
    }

    pub(crate) const fn ingress_request_id(&self) -> [u8; 16] {
        self.ingress_request_id
    }

    pub(crate) fn request_id(&self) -> Result<SessionConsensusRequestId, StoreError> {
        Ok(roster_consensus_request_id(self.admission_slot()?))
    }

    pub(crate) fn admission_slot(&self) -> Result<[u8; 32], StoreError> {
        Ok(roster_admission_slot(&self.admission))
    }

    pub(crate) fn immutable_payload_digest(&self) -> Result<[u8; 32], StoreError> {
        Ok(self.digest_cache.immutable_payload_digest)
    }

    /// Bind the exact replicated attempt, including its connection-issued
    /// ingress statement. This is response correlation only: the stable
    /// request ID and immutable body digest remain unchanged.
    pub(crate) fn exact_attempt_digest(&self) -> Result<[u8; 32], StoreError> {
        Ok(self.digest_cache.exact_attempt_digest)
    }

    pub(crate) fn outcome_binding(&self) -> Result<ConsensusRosterOutcomeBinding, StoreError> {
        ConsensusRosterOutcomeBinding::for_admission(self)
    }
}

impl fmt::Debug for ConsensusRosterAdmissionCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusRosterAdmissionCommand(<redacted>)")
    }
}

#[derive(Serialize, Deserialize)]
struct ConsensusRosterAdmissionWire {
    admission: BoundedRosterCapsule<MAX_ADMISSION_CODEC_BYTES>,
    authority: ConsensusRosterAuthorityWire,
    ingress_request_id: [u8; 16],
    ingress_attestation: BoundedRosterCapsule<MAX_ROSTER_INGRESS_ATTESTATION_BYTES>,
    admission_provenance: BoundedRosterCapsule<MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES>,
}

impl Serialize for ConsensusRosterAdmissionCommand {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let admission = self
            .admission
            .to_canonical_bytes()
            .map_err(serde::ser::Error::custom)?;
        ConsensusRosterAdmissionWire {
            admission: BoundedRosterCapsule::new(admission).map_err(serde::ser::Error::custom)?,
            authority: (&self.authority).into(),
            ingress_request_id: self.ingress_request_id,
            ingress_attestation: self.ingress_attestation.clone(),
            admission_provenance: self.admission_provenance.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConsensusRosterAdmissionCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ConsensusRosterAdmissionWire::deserialize(deserializer)?;
        let admission = Admission::from_canonical_bytes(&wire.admission.into_inner())
            .map_err(serde::de::Error::custom)?;
        let authority = wire
            .authority
            .into_authority()
            .map_err(serde::de::Error::custom)?;
        let ingress = RosterIngressAttestationV1::decode_canonical(&wire.ingress_attestation.0)
            .map_err(serde::de::Error::custom)?;
        let provenance =
            RosterCompactAdmissionProvenanceV2::decode_canonical(&wire.admission_provenance.0)
                .map_err(serde::de::Error::custom)?;
        Self::new_with_provenance_and_ingress_request_id(
            admission,
            authority,
            wire.ingress_request_id,
            ingress,
            provenance,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// The sole replicated Established-or-Aborted roster terminal mutation.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct ConsensusRosterTerminalCommand {
    binding: RequestBindingKey,
    registration_handle: [u8; 32],
    registration_request_id: RosterRequestId,
    registration_terminal_slot: [u8; 32],
    authority: AuthorityBinding,
    record: BoundedRosterCapsule<MAX_TERMINAL_CODEC_BYTES>,
    proof_bundle: BoundedRosterCapsule<MAX_EXECUTOR_PROOF_BUNDLE_BYTES>,
    terminal_evidence: BoundedRosterCapsule<MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES>,
    ingress_request_id: [u8; 16],
    ingress_attestation: BoundedRosterCapsule<MAX_ROSTER_INGRESS_ATTESTATION_BYTES>,
    digest_cache: ConsensusRosterCommandDigestCache,
}

/// Immutable terminal command body kept separate from its replaceable guards.
#[doc(hidden)]
pub(crate) struct ConsensusRosterTerminalCommandInput {
    pub(crate) binding: RequestBindingKey,
    pub(crate) registration_handle: [u8; 32],
    pub(crate) registration_request_id: RosterRequestId,
    pub(crate) registration_terminal_slot: [u8; 32],
    pub(crate) authority: AuthorityBinding,
    pub(crate) record: Vec<u8>,
}

impl ConsensusRosterTerminalCommand {
    fn new_from_parts(
        input: ConsensusRosterTerminalCommandInput,
        proof_bundle: BoundedRosterCapsule<MAX_EXECUTOR_PROOF_BUNDLE_BYTES>,
        terminal_evidence: BoundedRosterCapsule<MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES>,
        ingress_request_id: [u8; 16],
        ingress_attestation: BoundedRosterCapsule<MAX_ROSTER_INGRESS_ATTESTATION_BYTES>,
    ) -> Result<Self, StoreError> {
        let ConsensusRosterTerminalCommandInput {
            binding,
            registration_handle,
            registration_request_id,
            registration_terminal_slot,
            authority,
            record,
        } = input;
        if registration_handle == [0; 32]
            || registration_terminal_slot == [0; 32]
            || record.is_empty()
            || binding.history_epoch() != registration_request_id.history_epoch()
        {
            return Err(roster_command_rejected());
        }
        // A terminal command does not carry the retained admission required
        // for full authorization, but this canonical self-contained check
        // makes malformed record bytes unable to acquire a cached digest.
        TerminalRecord::canonical_body_commitment(&record)
            .map_err(|_| roster_command_rejected())?;
        let record = BoundedRosterCapsule::new(record)?;
        let digest_cache = roster_terminal_digest_cache(RosterTerminalDigestCacheInput {
            binding,
            registration_handle,
            registration_request_id,
            registration_terminal_slot,
            authority: &authority,
            record: &record.0,
            proof_bundle: &proof_bundle.0,
            terminal_evidence: &terminal_evidence.0,
            ingress_request_id,
            ingress_attestation: &ingress_attestation.0,
        })?;
        Ok(Self {
            binding,
            registration_handle,
            registration_request_id,
            registration_terminal_slot,
            authority,
            record,
            proof_bundle,
            terminal_evidence,
            ingress_request_id,
            ingress_attestation,
            digest_cache,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_proof_bundle(
        input: ConsensusRosterTerminalCommandInput,
        proof_bundle: RosterExecutorProofBundleV1,
    ) -> Result<Self, StoreError> {
        let proof_bundle = BoundedRosterCapsule::new(
            proof_bundle
                .canonical_bytes()
                .map_err(|_| roster_command_rejected())?,
        )?;
        Self::new_from_parts(
            input,
            proof_bundle,
            BoundedRosterCapsule::new(Vec::new())?,
            [0; 16],
            BoundedRosterCapsule::new(Vec::new())?,
        )
    }

    /// Construct the only production terminal command form.  Raw V1 proofs
    /// remain for the initial correspondence check, while compact V2 evidence
    /// is retained so followers and later compaction can verify the same
    /// terminal without raw provider evidence.
    pub(crate) fn new_with_proof_bundle_evidence_and_ingress_request_id(
        input: ConsensusRosterTerminalCommandInput,
        proof_bundle: RosterExecutorProofBundleV1,
        terminal_evidence: RosterCompactTerminalEvidenceV2,
        ingress_request_id: [u8; 16],
        ingress_attestation: RosterIngressAttestationV1,
    ) -> Result<Self, StoreError> {
        if ingress_request_id == [0; 16] || ingress_attestation.request_id() != ingress_request_id {
            return Err(roster_command_rejected());
        }
        let proof_bundle = BoundedRosterCapsule::new(
            proof_bundle
                .canonical_bytes()
                .map_err(|_| roster_command_rejected())?,
        )?;
        Self::new_from_parts(
            input,
            proof_bundle,
            BoundedRosterCapsule::new(
                terminal_evidence
                    .canonical_bytes()
                    .map_err(|_| roster_command_rejected())?,
            )?,
            ingress_request_id,
            BoundedRosterCapsule::new(
                ingress_attestation
                    .canonical_bytes()
                    .map_err(|_| roster_command_rejected())?,
            )?,
        )
    }

    pub(crate) const fn binding(&self) -> RequestBindingKey {
        self.binding
    }

    pub(crate) const fn registration_parts(&self) -> ([u8; 32], RosterRequestId, [u8; 32]) {
        (
            self.registration_handle,
            self.registration_request_id,
            self.registration_terminal_slot,
        )
    }

    pub(crate) fn authority(&self) -> &AuthorityBinding {
        &self.authority
    }

    pub(crate) fn record_bytes(&self) -> &[u8] {
        &self.record.0
    }

    pub(crate) fn proof_bundle(&self) -> Result<RosterExecutorProofBundleV1, StoreError> {
        RosterExecutorProofBundleV1::decode_canonical(&self.proof_bundle.0)
            .map_err(|_| roster_command_rejected())
    }

    /// Decode the exact compact terminal evidence retained beside the raw V1
    /// bundle in this initial command.
    pub(crate) fn terminal_evidence(&self) -> Result<RosterCompactTerminalEvidenceV2, StoreError> {
        RosterCompactTerminalEvidenceV2::decode_canonical(&self.terminal_evidence.0)
            .map_err(|_| roster_command_rejected())
    }

    pub(crate) fn ingress_attestation(&self) -> Result<RosterIngressAttestationV1, StoreError> {
        RosterIngressAttestationV1::decode_canonical(&self.ingress_attestation.0)
            .map_err(|_| roster_command_rejected())
    }

    pub(crate) const fn ingress_request_id(&self) -> [u8; 16] {
        self.ingress_request_id
    }

    pub(crate) fn request_id(&self) -> Result<SessionConsensusRequestId, StoreError> {
        Ok(roster_consensus_request_id(self.terminal_slot()?))
    }

    pub(crate) fn terminal_slot(&self) -> Result<[u8; 32], StoreError> {
        Ok(self.registration_terminal_slot)
    }

    pub(crate) fn immutable_payload_digest(&self) -> [u8; 32] {
        self.digest_cache.immutable_payload_digest
    }

    /// Bind the exact replaceable current authority, SDK proof bundle, and
    /// ingress statement used by this terminal attempt without changing its
    /// stable idempotency identity.
    pub(crate) fn exact_attempt_digest(&self) -> Result<[u8; 32], StoreError> {
        Ok(self.digest_cache.exact_attempt_digest)
    }

    pub(crate) fn outcome_binding(&self) -> Result<ConsensusRosterOutcomeBinding, StoreError> {
        ConsensusRosterOutcomeBinding::for_terminal(self)
    }
}

impl fmt::Debug for ConsensusRosterTerminalCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusRosterTerminalCommand(<redacted>)")
    }
}

#[derive(Serialize, Deserialize)]
struct ConsensusRosterTerminalWire {
    binding: RequestBindingKey,
    registration_handle: [u8; 32],
    registration_request_id: RosterRequestId,
    registration_terminal_slot: [u8; 32],
    authority: ConsensusRosterAuthorityWire,
    record: BoundedRosterCapsule<MAX_TERMINAL_CODEC_BYTES>,
    proof_bundle: BoundedRosterCapsule<MAX_EXECUTOR_PROOF_BUNDLE_BYTES>,
    terminal_evidence: BoundedRosterCapsule<MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES>,
    ingress_request_id: [u8; 16],
    ingress_attestation: BoundedRosterCapsule<MAX_ROSTER_INGRESS_ATTESTATION_BYTES>,
}

impl Serialize for ConsensusRosterTerminalCommand {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        ConsensusRosterTerminalWire {
            binding: self.binding,
            registration_handle: self.registration_handle,
            registration_request_id: self.registration_request_id,
            registration_terminal_slot: self.registration_terminal_slot,
            authority: (&self.authority).into(),
            record: self.record.clone(),
            proof_bundle: self.proof_bundle.clone(),
            terminal_evidence: self.terminal_evidence.clone(),
            ingress_request_id: self.ingress_request_id,
            ingress_attestation: self.ingress_attestation.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ConsensusRosterTerminalCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ConsensusRosterTerminalWire::deserialize(deserializer)?;
        let authority = wire
            .authority
            .into_authority()
            .map_err(serde::de::Error::custom)?;
        let proof_bundle = RosterExecutorProofBundleV1::decode_canonical(&wire.proof_bundle.0)
            .map_err(serde::de::Error::custom)?;
        let terminal_evidence =
            RosterCompactTerminalEvidenceV2::decode_canonical(&wire.terminal_evidence.0)
                .map_err(serde::de::Error::custom)?;
        let ingress = RosterIngressAttestationV1::decode_canonical(&wire.ingress_attestation.0)
            .map_err(serde::de::Error::custom)?;
        Self::new_with_proof_bundle_evidence_and_ingress_request_id(
            ConsensusRosterTerminalCommandInput {
                binding: wire.binding,
                registration_handle: wire.registration_handle,
                registration_request_id: wire.registration_request_id,
                registration_terminal_slot: wire.registration_terminal_slot,
                authority,
                record: wire.record.into_inner(),
            },
            proof_bundle,
            terminal_evidence,
            wire.ingress_request_id,
            ingress,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// State-machine-issued correlation for one exact roster command outcome.
///
/// A forwarding response does not otherwise echo its request identity. Every
/// roster outcome therefore carries the derived consensus request ID, the
/// takeover-stable immutable payload digest, and an exact-attempt digest. A
/// lost or misrouted response cannot become a definitive result for another
/// body, guard, proof bundle, or ingress statement.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusRosterOutcomeBinding {
    request_id: SessionConsensusRequestId,
    immutable_payload_digest: [u8; 32],
    exact_attempt_digest: [u8; 32],
}

impl ConsensusRosterOutcomeBinding {
    pub(crate) fn for_admission(
        command: &ConsensusRosterAdmissionCommand,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            request_id: command.request_id()?,
            immutable_payload_digest: command.immutable_payload_digest()?,
            exact_attempt_digest: command.exact_attempt_digest()?,
        })
    }

    pub(crate) fn for_terminal(
        command: &ConsensusRosterTerminalCommand,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            request_id: command.request_id()?,
            immutable_payload_digest: command.immutable_payload_digest(),
            exact_attempt_digest: command.exact_attempt_digest()?,
        })
    }

    pub(crate) fn matches_admission(
        self,
        command: &ConsensusRosterAdmissionCommand,
    ) -> Result<bool, StoreError> {
        Ok(self == Self::for_admission(command)?)
    }

    pub(crate) fn matches_terminal(
        self,
        command: &ConsensusRosterTerminalCommand,
    ) -> Result<bool, StoreError> {
        Ok(self == Self::for_terminal(command)?)
    }
}

#[cfg(test)]
fn roster_command_attempt_digest_reference(
    operation_tag: u8,
    command: &impl Serialize,
) -> Result<[u8; 32], StoreError> {
    let canonical = postcard::to_allocvec(command).map_err(|_| roster_command_rejected())?;
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_COMMAND_ATTEMPT_DIGEST_DOMAIN);
    hasher.update([operation_tag]);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    Ok(hasher.finalize().into())
}

impl fmt::Debug for ConsensusRosterOutcomeBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusRosterOutcomeBinding(<redacted>)")
    }
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusRosterAdmissionOutcome {
    Admitted {
        outcome_binding: ConsensusRosterOutcomeBinding,
        slot: [u8; 32],
        binding: Box<RequestBindingKey>,
        registration_handle: [u8; 32],
        registration_request_id: RosterRequestId,
        registration_terminal_slot: [u8; 32],
    },
    Rejected {
        outcome_binding: ConsensusRosterOutcomeBinding,
        rejection: ConsensusRosterRejection,
    },
    /// A valid admission command whose stable slot was already durably
    /// registered. This deliberately carries no registration capability or
    /// compact provenance: callers must recover through the read-only path.
    Replayed {
        outcome_binding: ConsensusRosterOutcomeBinding,
    },
}

impl ConsensusRosterAdmissionOutcome {
    pub(crate) fn admitted(
        command: &ConsensusRosterAdmissionCommand,
        registration: BackendRegistration,
    ) -> Result<Self, StoreError> {
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            registration.consensus_parts();
        Ok(Self::Admitted {
            outcome_binding: command.outcome_binding()?,
            slot: command.admission_slot()?,
            binding: Box::new(
                command
                    .admission()
                    .binding_key(registration_request_id.history_epoch())
                    .map_err(|_| roster_command_rejected())?,
            ),
            registration_handle,
            registration_request_id,
            registration_terminal_slot: *registration_terminal_slot.as_bytes(),
        })
    }

    pub(crate) fn rejected(
        command: &ConsensusRosterAdmissionCommand,
        rejection: ConsensusRosterRejection,
    ) -> Result<Self, StoreError> {
        Ok(Self::Rejected {
            outcome_binding: command.outcome_binding()?,
            rejection,
        })
    }

    pub(crate) fn replayed(command: &ConsensusRosterAdmissionCommand) -> Result<Self, StoreError> {
        Ok(Self::Replayed {
            outcome_binding: command.outcome_binding()?,
        })
    }
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusRosterTerminalOutcome {
    Committed {
        outcome_binding: ConsensusRosterOutcomeBinding,
        slot: [u8; 32],
        replayed: bool,
        committed: BoundedRosterCapsule<MAX_COMMITTED_TERMINAL_CODEC_BYTES>,
    },
    Compacted {
        outcome_binding: ConsensusRosterOutcomeBinding,
        slot: [u8; 32],
        history_epoch: u64,
        tombstone: BoundedRosterCapsule<MAX_TOMBSTONE_CODEC_BYTES>,
    },
    Rejected {
        outcome_binding: ConsensusRosterOutcomeBinding,
        rejection: ConsensusRosterRejection,
    },
}

impl ConsensusRosterTerminalOutcome {
    pub(crate) fn committed(
        command: &ConsensusRosterTerminalCommand,
        replayed: bool,
        committed: &CommittedTerminal,
        admission: &Admission,
    ) -> Result<Self, StoreError> {
        let committed = committed
            .to_canonical_bytes(admission)
            .map_err(|_| roster_command_rejected())?;
        Ok(Self::Committed {
            outcome_binding: command.outcome_binding()?,
            slot: command.terminal_slot()?,
            replayed,
            committed: BoundedRosterCapsule::new(committed)?,
        })
    }

    pub(crate) fn compacted(
        command: &ConsensusRosterTerminalCommand,
        history_epoch: u64,
        tombstone: TerminalConflictTombstone,
    ) -> Result<Self, StoreError> {
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            command.registration_parts();
        if registration_handle != roster_registration_handle(command.binding())
            || history_epoch != command.binding().history_epoch()
            || history_epoch != registration_request_id.history_epoch()
        {
            return Err(roster_command_rejected());
        }
        let terminal_body_commitment =
            TerminalRecord::canonical_body_commitment(command.record_bytes())
                .map_err(|_| roster_command_rejected())?;
        tombstone
            .validate_compacted_terminal(
                command.binding(),
                registration_request_id,
                registration_terminal_slot,
                command.authority().fence(),
                command.authority().generation(),
                terminal_body_commitment,
            )
            .map_err(|_| roster_command_rejected())?;
        let tombstone = BoundedRosterCapsule::new(
            tombstone
                .to_canonical_bytes()
                .map_err(|_| roster_command_rejected())?,
        )?;
        Ok(Self::Compacted {
            outcome_binding: command.outcome_binding()?,
            slot: command.terminal_slot()?,
            history_epoch,
            tombstone,
        })
    }

    pub(crate) fn rejected(
        command: &ConsensusRosterTerminalCommand,
        rejection: ConsensusRosterRejection,
    ) -> Result<Self, StoreError> {
        Ok(Self::Rejected {
            outcome_binding: command.outcome_binding()?,
            rejection,
        })
    }

    pub(crate) fn committed_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Committed { committed, .. } => Some(&committed.0),
            Self::Compacted { .. } | Self::Rejected { .. } => None,
        }
    }

    pub(crate) fn compacted_parts(
        &self,
    ) -> Result<Option<(u64, TerminalConflictTombstone)>, StoreError> {
        match self {
            Self::Compacted {
                history_epoch,
                tombstone,
                ..
            } => Ok(Some((
                *history_epoch,
                TerminalConflictTombstone::from_canonical_bytes(&tombstone.0)
                    .map_err(|_| roster_command_rejected())?,
            ))),
            Self::Committed { .. } | Self::Rejected { .. } => Ok(None),
        }
    }

    pub(crate) const fn is_replayed(&self) -> bool {
        matches!(self, Self::Committed { replayed: true, .. })
    }
}

#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusRosterRejection {
    Authority,
    RecoveryRequired,
    TerminalLocked,
    TerminalConflict,
    RecordMissing,
    GenerationConflict,
    GenerationExhausted,
    BusinessKeyReserved,
    InvalidProtectedCheckpoint,
    AggregateBytesFull,
    LiveFull,
    HistoryFull,
}

impl fmt::Debug for ConsensusRosterAdmissionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusRosterAdmissionOutcome(<redacted>)")
    }
}

impl fmt::Debug for ConsensusRosterTerminalOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusRosterTerminalOutcome(<redacted>)")
    }
}

impl fmt::Debug for ConsensusRosterRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusRosterRejection(<redacted>)")
    }
}

/// High-level mutation submitted to the current consensus leader.
///
/// Allocation of fences, credentials, effective logical time, application
/// sequence, and the digest predecessor remains committed state-machine work
/// and cannot be chosen by an authenticated follower.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionMutationIntent {
    /// Advance the persisted logical clock without changing session data.
    ///
    /// Consensus-backed reads use this barrier before evaluating TTLs so a
    /// leader failover cannot move observed time backwards and resurrect an
    /// expired lease or record.
    AdvanceLogicalTime,
    /// Compare and set one record under a fenced lease.
    ///
    /// The shared ownership is runtime-only: serde still emits exactly the
    /// wrapped operation.  It lets a forwarding request survive a proven
    /// before-transmission leader reroute without cloning sealed ciphertext.
    CompareAndSet(Arc<CompareAndSet>),
    /// Delete one record under a fenced lease.
    DeleteFenced(LeaseGuard),
    /// Refresh a record TTL under a fenced lease.
    RefreshTtl {
        /// Existing fenced lease.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: std::time::Duration,
    },
    /// Acquire a new lease and allocate the next fence/credential pair.
    AcquireLease {
        /// Session key to lease.
        key: SessionKey,
        /// Requested owner.
        owner: OwnerId,
        /// Requested bounded TTL.
        ttl: std::time::Duration,
    },
    /// Renew an existing lease.
    RenewLease {
        /// Existing fenced lease.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: std::time::Duration,
    },
    /// Release an existing lease.
    ReleaseLease(LeaseGuard),
    /// SDK-internal quorum-durable binding of a caller-owned consumer request
    /// ID to one full request commitment.
    #[doc(hidden)]
    BindConsumerRequest {
        /// SHA-256 commitment to the complete typed consumer request.
        request_commitment: [u8; 32],
    },
    /// SDK-internal durable receipt for a consumer batch point read.
    ///
    /// A batch is retryable only if every slot has a stable durable outcome.
    /// The result is retained only in the consensus idempotency receipt and
    /// never becomes a replication entry or consumer-controlled replay API.
    #[doc(hidden)]
    ReadConsumerRecord {
        /// Key read at the command's committed logical time.
        key: SessionKey,
    },
    /// SDK-internal operator recovery fence committed only through the local
    /// leader's authorized admin boundary.
    #[doc(hidden)]
    FinalizeOperatorRecovery {
        /// Monotonic operator recovery epoch.
        recovery_epoch: u64,
        /// Digest of the exact inspected and confirmed recovery plan.
        plan_digest: [u8; 32],
        /// Highest fence observed across every inspected replica.
        fence_high_water: u64,
        /// Highest credential ID observed across every inspected replica.
        credential_high_water: u64,
    },
    /// SDK-internal durable preparation for one exact topology transition.
    #[doc(hidden)]
    PrepareTopologyTransition {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
        /// Exact successor cluster/configuration/epoch identity.
        desired_identity: SessionConsensusIdentity,
        /// Exact successor voter IDs.
        desired_members: BTreeSet<SessionConsensusNodeId>,
        /// Redacted exact descriptor and uniqueness bindings by voter ID.
        desired_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    },
    /// SDK-internal durable proof that every added learner caught up.
    #[doc(hidden)]
    MarkTopologyLearnersReady {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
    },
    /// SDK-internal authority cutover committed before joint consensus.
    #[doc(hidden)]
    FenceTopologyAuthority {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
    },
    /// SDK-internal rollback of a transition that never committed joint state.
    #[doc(hidden)]
    AbortTopologyTransition {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
    },
    /// SDK-internal terminal marker after the desired uniform epoch commits.
    #[doc(hidden)]
    FinalizeTopologyTransition {
        /// Opaque caller-owned transition identity.
        transition_id: [u8; 16],
        /// Digest of the complete validated transition request.
        request_digest: [u8; 32],
    },
    /// SDK-internal authenticated application-authority envelope.
    ///
    /// The consensus store constructs this only after authenticating the
    /// forwarding replica. Callers submit the enclosed mutation directly and
    /// cannot assert their own topology authority.
    #[doc(hidden)]
    Authorized {
        /// Authenticated logical origin of the application mutation.
        origin: SessionConsensusNodeId,
        /// Exact cluster/configuration/epoch authority that admitted `origin`.
        authority_identity: SessionConsensusIdentity,
        /// Original caller mutation. Nested authority or topology-control
        /// intents are rejected by the state machine.
        mutation: Box<SessionMutationIntent>,
    },
    /// Atomically acquire or renew one exact fence and mutate the same record.
    FencedTransition(Box<FencedTransitionRequest>),
    /// The first V1 fenced transition for one exact voter scope.
    ///
    /// This is intentionally an internal command shape rather than a separate
    /// admin request: its receipt, activation certificate, lease, and record
    /// effect commit at exactly the caller's one transition log position.
    #[doc(hidden)]
    ActivateFencedTransition {
        /// Original caller-owned transition.
        request: Box<FencedTransitionRequest>,
        /// Exact current authority scope observed during unanimous V1 proof.
        scope_identity: SessionConsensusIdentity,
        /// Canonical digest of the exact voter IDs in that scope.
        voter_set_digest: [u8; 32],
    },
    /// Atomically apply one V2 fenced transition.
    ///
    /// This is deliberately a distinct replicated intent rather than a V1
    /// command selected by local apply state.  Every replica therefore applies
    /// the fixed V2 receipt/history semantics encoded by this log entry.
    FencedTransitionV2(Box<FencedTransitionV2Request>),
    /// The first V2 fenced transition for one exact voter scope and immutable
    /// V2 history profile.
    ///
    /// The activation certificate, exact request receipt, and transition
    /// effect are one replicated command.  `profile_digest` binds the fixed
    /// V2 schema and limits that all voters freshly confirmed before proposal.
    #[doc(hidden)]
    ActivateFencedTransitionV2 {
        /// Original caller-owned V2 transition.
        request: Box<FencedTransitionV2Request>,
        /// Exact current authority scope observed during unanimous V2 proof.
        scope_identity: SessionConsensusIdentity,
        /// Canonical digest of the exact voter IDs in that scope.
        voter_set_digest: [u8; 32],
        /// Digest of V2's fixed serialized schema and history limits.
        profile_digest: [u8; 32],
    },
    /// SDK-internal bounded V2 receipt-history maintenance.
    ///
    /// This is an explicit replicated maintenance command with compare-and-set
    /// state, never a local compaction side effect.  Only the existing local
    /// operator-recovery authority may submit it.
    #[doc(hidden)]
    MaintainFencedTransitionV2History {
        /// Durable V2 history generation observed before maintenance admission.
        expected_generation: u64,
        /// Active V2 history epoch observed before maintenance admission.
        expected_active_epoch: Option<FencedTransitionV2HistoryEpoch>,
        /// Highest permanently retired V2 history epoch observed before
        /// maintenance admission.
        expected_retired_through: u64,
        /// Number of bound receipts observed in the active epoch before
        /// maintenance admission. This makes the maintenance CAS fail closed
        /// if a concurrently committed V2 request filled or extended the
        /// active epoch without changing the lifecycle generation.
        expected_bound_entries: u64,
    },
    /// Coalesce an ordered, same-epoch batch of independent V2 fenced
    /// transitions into one replicated command.
    ///
    /// Each item retains its complete self-authenticating 56-byte request ID.
    /// The store layer derives the command's outer id from those ordered full
    /// IDs; this replicated vocabulary deliberately never truncates or
    /// replaces them with a batch-local identity. One physical log entry is a
    /// throughput optimization only: items have independent logical effects,
    /// results, and singleton status identities. This is not an inter-item
    /// conditional or all-or-nothing distributed transaction.
    FencedTransitionV2Batch(Vec<FencedTransitionV2Request>),
    /// SDK-internal request to durably activate V1 for the current exact voter
    /// scope. This is appended after V2 to preserve every already-published
    /// V2 postcard discriminant.
    #[doc(hidden)]
    PreflightFencedTransitionCapability,
    /// SDK-internal cluster-scope V1 activation certificate, also appended to
    /// preserve V2 wire compatibility. The leader derives these fields from
    /// its exact scope after the preflight's typed admission and unanimous
    /// probes; raw callers cannot submit this shape.
    #[doc(hidden)]
    ActivateFencedTransitionCapability {
        /// Exact V1 protocol schema admitted by every voter.
        schema_version: u16,
        /// Exact current authority scope observed during unanimous V1 proof.
        scope_identity: SessionConsensusIdentity,
        /// Canonical digest of the exact voter IDs in that scope.
        voter_set_digest: [u8; 32],
    },
    /// SDK-internal atomic immutable protected-roster admission.
    #[doc(hidden)]
    RosterAdmission(Box<ConsensusRosterAdmissionCommand>),
    /// SDK-internal atomic Established-or-Aborted protected-roster terminalization.
    #[doc(hidden)]
    RosterTerminal(Box<ConsensusRosterTerminalCommand>),
    /// SDK-internal unanimous exact-profile proof for the immutable protected
    /// roster protocol. The leader turns this into the existing bounded
    /// activation certificate only after every current voter confirms the
    /// frozen profile; it must never reach the replicated log directly.
    #[doc(hidden)]
    PreflightProtectedRosterProfile,
}

impl fmt::Debug for SessionMutationIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionMutationIntent(<redacted>)")
    }
}

/// Application command carried by one normal Openraft log entry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsensusCommand {
    /// Exact durable command schema.
    pub schema_version: u16,
    /// Cluster/configuration/epoch scope.
    pub identity: SessionConsensusIdentity,
    /// Durable request identity used for idempotent outcome lookup.
    pub request_id: SessionConsensusRequestId,
    /// Leader-observed time carried as deterministic command input. The state
    /// machine takes the maximum of this value and its last committed logical
    /// time, so an in-flight proposal or clock rollback cannot regress expiry.
    pub logical_time: opc_types::Timestamp,
    /// High-level deterministic mutation.
    pub intent: SessionMutationIntent,
}

impl fmt::Debug for SessionConsensusCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsensusCommand(<redacted>)")
    }
}

impl SessionConsensusCommand {
    /// Calculate the domain-separated digest of the committed application
    /// chain position and its command.
    pub fn calculate_applied_digest(
        &self,
        sequence: u64,
        previous_digest: SessionConsensusEntryDigest,
        effective_logical_time: opc_types::Timestamp,
    ) -> Result<SessionConsensusEntryDigest, StoreError> {
        let (domain, encoded) = if self.intent.contains_roster_command() {
            (
                ROSTER_APPLIED_DIGEST_DOMAIN,
                self.encode_roster_applied_digest_input(
                    sequence,
                    previous_digest,
                    effective_logical_time,
                )?,
            )
        } else if self.intent.contains_fenced_transition_v2() {
            (
                COMMAND_V2_DIGEST_DOMAIN,
                self.encode_v2_applied_digest_input(
                    sequence,
                    previous_digest,
                    effective_logical_time,
                )?,
            )
        } else {
            (
                COMMAND_DIGEST_DOMAIN,
                serde_json::to_vec(&(sequence, previous_digest, effective_logical_time, self))
                    .map_err(|_| {
                        StoreError::Serialization(
                            "session consensus command encoding failed".into(),
                        )
                    })?,
            )
        };
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(encoded);
        Ok(SessionConsensusEntryDigest::from_bytes(
            hasher.finalize().into(),
        ))
    }

    fn encode_v2_applied_digest_input(
        &self,
        sequence: u64,
        previous_digest: SessionConsensusEntryDigest,
        effective_logical_time: opc_types::Timestamp,
    ) -> Result<Vec<u8>, StoreError> {
        let mut encoded = Vec::with_capacity(256);
        encoded.extend_from_slice(COMMAND_V2_DIGEST_MAGIC);
        encoded
            .extend_from_slice(&SESSION_CONSENSUS_V2_APPLIED_DIGEST_ENCODING_VERSION.to_be_bytes());
        encoded.extend_from_slice(&sequence.to_be_bytes());
        encoded.extend_from_slice(previous_digest.as_bytes());
        append_v2_applied_timestamp(&mut encoded, effective_logical_time);
        encoded.extend_from_slice(&self.schema_version.to_be_bytes());
        append_v2_applied_identity(&mut encoded, self.identity);
        encoded.extend_from_slice(self.request_id.as_bytes());
        append_v2_applied_timestamp(&mut encoded, self.logical_time);
        append_v2_applied_intent(&mut encoded, &self.intent)?;
        Ok(encoded)
    }

    /// Encode the fixed-width applied-digest input for a protected roster
    /// command.  The inner command is represented by its cached exact
    /// canonical Postcard digest, rather than by another JSON traversal of
    /// its bounded opaque bodies.
    fn encode_roster_applied_digest_input(
        &self,
        sequence: u64,
        previous_digest: SessionConsensusEntryDigest,
        effective_logical_time: opc_types::Timestamp,
    ) -> Result<Vec<u8>, StoreError> {
        let mut encoded = Vec::with_capacity(192);
        encoded.extend_from_slice(ROSTER_APPLIED_DIGEST_MAGIC);
        encoded.extend_from_slice(
            &SESSION_CONSENSUS_ROSTER_APPLIED_DIGEST_ENCODING_VERSION.to_be_bytes(),
        );
        encoded.extend_from_slice(&sequence.to_be_bytes());
        encoded.extend_from_slice(previous_digest.as_bytes());
        append_v2_applied_timestamp(&mut encoded, effective_logical_time);
        encoded.extend_from_slice(&self.schema_version.to_be_bytes());
        append_v2_applied_identity(&mut encoded, self.identity);
        encoded.extend_from_slice(self.request_id.as_bytes());
        append_v2_applied_timestamp(&mut encoded, self.logical_time);
        append_roster_applied_intent(&mut encoded, &self.intent)?;
        Ok(encoded)
    }
}

impl SessionMutationIntent {
    fn contains_roster_command(&self) -> bool {
        matches!(self, Self::RosterAdmission(_) | Self::RosterTerminal(_))
            || matches!(self, Self::Authorized { mutation, .. } if matches!(
                mutation.as_ref(),
                Self::RosterAdmission(_) | Self::RosterTerminal(_)
            ))
    }

    fn contains_fenced_transition_v2(&self) -> bool {
        matches!(
            self,
            Self::FencedTransitionV2(_)
                | Self::FencedTransitionV2Batch(_)
                | Self::ActivateFencedTransitionV2 { .. }
                | Self::MaintainFencedTransitionV2History { .. }
        ) || matches!(self, Self::Authorized { mutation, .. } if mutation.contains_fenced_transition_v2())
    }
}

/// Validate the fixed V2 batch request profile before a command can have an
/// effect.
///
/// The full vector is encoded with the same bounded Postcard codec used by
/// consensus transport.  This intentionally measures the whole encoded input
/// rather than summing estimates of nested request bodies.
pub(crate) fn validate_fenced_transition_v2_batch(
    requests: &[FencedTransitionV2Request],
) -> Result<(), StoreError> {
    if requests.is_empty() || requests.len() > MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS {
        return Err(StoreError::InvalidKey(
            "fenced_transition_v2_batch_count_invalid".into(),
        ));
    }
    let epoch = requests[0].request_id().epoch();
    let mut ids = BTreeSet::new();
    for request in requests {
        // Retain an otherwise structurally valid substituted body for
        // deterministic request-conflict handling, matching singleton V2.
        match request.validate() {
            Ok(()) | Err(StoreError::FencedTransitionRequestConflict) => {}
            Err(error) => return Err(error),
        }
        if request.request_id().epoch() != epoch {
            return Err(StoreError::InvalidKey(
                "fenced_transition_v2_batch_epoch_mismatch".into(),
            ));
        }
        if !ids.insert(request.request_id().to_bytes()) {
            return Err(StoreError::InvalidKey(
                "fenced_transition_v2_batch_duplicate_request_id".into(),
            ));
        }
    }
    validate_fenced_transition_v2_batch_encoded_bytes(
        requests,
        MAX_SESSION_FENCED_TRANSITION_V2_BATCH_REQUEST_BYTES,
        "fenced_transition_v2_batch_request_encoding_failed",
    )
}

/// Derive the durable outer request ID for one validated ordered V2 batch.
///
/// This is intentionally not a caller-controlled batch identity. It binds
/// the ordered complete 56-byte item IDs (and the count) under a dedicated
/// domain so a reordered batch or any substituted item cannot reuse a
/// consensus idempotency receipt.
pub(crate) fn fenced_transition_v2_batch_outer_request_id(
    requests: &[FencedTransitionV2Request],
) -> Result<[u8; 16], StoreError> {
    validate_fenced_transition_v2_batch(requests)?;
    let count = u16::try_from(requests.len()).map_err(|_| {
        StoreError::Serialization("session consensus V2 batch count encoding failed".into())
    })?;
    let mut hasher = Sha256::new();
    hasher.update(FENCED_TRANSITION_V2_BATCH_OUTER_REQUEST_ID_DOMAIN);
    hasher.update(count.to_be_bytes());
    for request in requests {
        hasher.update(request.request_id().to_bytes());
    }
    let digest: [u8; 32] = hasher.finalize().into();
    let mut outer = [0_u8; 16];
    outer.copy_from_slice(&digest[..16]);
    Ok(outer)
}

/// Validate the persisted V2 batch outcome vector before it is returned or
/// retained by a consensus adapter.
pub(crate) fn validate_fenced_transition_v2_batch_outcomes(
    outcomes: &[Result<FencedTransitionOutcome, StoreError>],
) -> Result<(), StoreError> {
    if outcomes.is_empty() || outcomes.len() > MAX_SESSION_FENCED_TRANSITION_V2_BATCH_OPERATIONS {
        return Err(StoreError::InvalidKey(
            "fenced_transition_v2_batch_outcome_count_invalid".into(),
        ));
    }
    validate_fenced_transition_v2_batch_encoded_bytes(
        outcomes,
        MAX_SESSION_FENCED_TRANSITION_V2_BATCH_RESPONSE_BYTES,
        "fenced_transition_v2_batch_outcome_encoding_failed",
    )
}

fn validate_fenced_transition_v2_batch_encoded_bytes<T>(
    value: &T,
    maximum: usize,
    encoding_error: &'static str,
) -> Result<(), StoreError>
where
    T: Serialize + ?Sized,
{
    let encoded = opc_consensus::encode_bounded(value)
        .map_err(|_| StoreError::InvalidKey(encoding_error.into()))?;
    if encoded.len() > maximum {
        return Err(StoreError::PayloadTooLarge {
            actual: encoded.len(),
            max: maximum,
        });
    }
    Ok(())
}

fn append_v2_applied_timestamp(out: &mut Vec<u8>, timestamp: opc_types::Timestamp) {
    let timestamp = timestamp.as_offset_datetime();
    out.extend_from_slice(&timestamp.unix_timestamp().to_be_bytes());
    out.extend_from_slice(&timestamp.nanosecond().to_be_bytes());
}

fn append_v2_applied_identity(out: &mut Vec<u8>, identity: SessionConsensusIdentity) {
    out.extend_from_slice(identity.cluster_id().as_bytes());
    out.extend_from_slice(identity.configuration_id().as_bytes());
    out.extend_from_slice(&identity.configuration_epoch().get().to_be_bytes());
}

fn append_v2_applied_intent(
    out: &mut Vec<u8>,
    intent: &SessionMutationIntent,
) -> Result<(), StoreError> {
    match intent {
        SessionMutationIntent::FencedTransitionV2(request) => {
            out.push(1);
            out.extend_from_slice(&request.request_id().to_bytes());
        }
        SessionMutationIntent::FencedTransitionV2Batch(requests) => {
            validate_fenced_transition_v2_batch(requests)?;
            out.push(5);
            out.extend_from_slice(
                &u16::try_from(requests.len())
                    .map_err(|_| {
                        StoreError::Serialization(
                            "session consensus V2 batch count encoding failed".into(),
                        )
                    })?
                    .to_be_bytes(),
            );
            for request in requests {
                out.extend_from_slice(&request.request_id().to_bytes());
            }
        }
        SessionMutationIntent::ActivateFencedTransitionV2 {
            request,
            scope_identity,
            voter_set_digest,
            profile_digest,
        } => {
            out.push(2);
            out.extend_from_slice(&request.request_id().to_bytes());
            append_v2_applied_identity(out, *scope_identity);
            out.extend_from_slice(voter_set_digest);
            out.extend_from_slice(profile_digest);
        }
        SessionMutationIntent::MaintainFencedTransitionV2History {
            expected_generation,
            expected_active_epoch,
            expected_retired_through,
            expected_bound_entries,
        } => {
            out.push(3);
            out.extend_from_slice(&expected_generation.to_be_bytes());
            match expected_active_epoch {
                None => out.push(0),
                Some(epoch) => {
                    out.push(1);
                    out.extend_from_slice(&epoch.get().to_be_bytes());
                }
            }
            out.extend_from_slice(&expected_retired_through.to_be_bytes());
            out.extend_from_slice(&expected_bound_entries.to_be_bytes());
        }
        SessionMutationIntent::Authorized {
            origin,
            authority_identity,
            mutation,
        } if mutation.contains_fenced_transition_v2() => {
            out.push(4);
            out.extend_from_slice(&origin.get().to_be_bytes());
            append_v2_applied_identity(out, *authority_identity);
            append_v2_applied_intent(out, mutation)?;
        }
        _ => {
            return Err(StoreError::Serialization(
                "session consensus V2 digest intent is invalid".into(),
            ));
        }
    }
    Ok(())
}

/// Append the exact direct-or-authorized roster shape.  The outer authority
/// envelope is deliberately not folded into the inner digest: it has its own
/// explicit tag and fixed encoding so an origin or authority substitution
/// extends a different applied-digest chain position.
fn append_roster_applied_intent(
    out: &mut Vec<u8>,
    intent: &SessionMutationIntent,
) -> Result<(), StoreError> {
    match intent {
        SessionMutationIntent::RosterAdmission(command) => {
            out.push(0);
            append_roster_applied_inner(out, 1, command.exact_attempt_digest()?);
        }
        SessionMutationIntent::RosterTerminal(command) => {
            out.push(0);
            append_roster_applied_inner(out, 2, command.exact_attempt_digest()?);
        }
        SessionMutationIntent::Authorized {
            origin,
            authority_identity,
            mutation,
        } => {
            out.push(1);
            out.extend_from_slice(&origin.get().to_be_bytes());
            append_v2_applied_identity(out, *authority_identity);
            match mutation.as_ref() {
                SessionMutationIntent::RosterAdmission(command) => {
                    append_roster_applied_inner(out, 1, command.exact_attempt_digest()?);
                }
                SessionMutationIntent::RosterTerminal(command) => {
                    append_roster_applied_inner(out, 2, command.exact_attempt_digest()?);
                }
                _ => {
                    return Err(StoreError::Serialization(
                        "session consensus roster digest intent is invalid".into(),
                    ));
                }
            }
        }
        _ => {
            return Err(StoreError::Serialization(
                "session consensus roster digest intent is invalid".into(),
            ));
        }
    }
    Ok(())
}

fn append_roster_applied_inner(out: &mut Vec<u8>, operation_tag: u8, digest: [u8; 32]) {
    out.push(operation_tag);
    out.extend_from_slice(&digest);
}

/// Successful state-machine result returned after durable quorum commit and
/// local application.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionMutationOutcome {
    /// Result of a compare-and-set command.
    CompareAndSet(CompareAndSetResult),
    /// Durable result of an SDK-internal consumer batch point read.
    #[doc(hidden)]
    ConsumerRecord(Option<StoredSessionRecord>),
    /// Lease allocated or renewed by the committed command.
    Lease(LeaseGuard),
    /// Mutation completed without a value result.
    Unit,
    /// Result of one atomic single-record fenced transition.
    FencedTransition(FencedTransitionOutcome),
    /// Ordered exact outcomes for one coalesced V2 fenced-transition batch.
    ///
    /// Position `n` corresponds to position `n` in the replicated batch
    /// intent. Consumer projections additionally carry each full request ID
    /// so callers never infer correlation from a truncated identifier. A
    /// successful item does not make sibling logical effects conditional or
    /// all-or-nothing.
    FencedTransitionV2Batch(Vec<Result<FencedTransitionOutcome, StoreError>>),
    /// Compact outcome of one immutable protected-roster admission.
    #[doc(hidden)]
    RosterAdmission(ConsensusRosterAdmissionOutcome),
    /// Compact outcome of one atomic protected-roster terminalization.
    #[doc(hidden)]
    RosterTerminal(ConsensusRosterTerminalOutcome),
}

impl fmt::Debug for SessionMutationOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionMutationOutcome(<redacted>)")
    }
}

/// Persisted command outcome returned by Openraft client writes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsensusResponse {
    /// Deterministic state-machine result. Errors are persisted so an exact
    /// retry returns the original outcome after restart or leader failover.
    pub result: Result<SessionMutationOutcome, StoreError>,
    /// Committed application sequence when admitted, or zero for a rejection.
    pub sequence: u64,
    /// Digest of the admitted application command.
    pub digest: Option<SessionConsensusEntryDigest>,
    /// Persisted logical time at which the original request was applied.
    /// Exact retries recover this value even after leader failover.
    pub logical_time: Option<opc_types::Timestamp>,
    /// Original Openraft log index that durably applied this request.
    /// Followers use it to wait for their local state machine before reading.
    pub raft_log_index: u64,
}

impl fmt::Debug for SessionConsensusResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsensusResponse(<redacted>)")
    }
}

impl SessionConsensusResponse {
    /// Construct a failed response that made no application-sequence advance.
    pub fn rejected(error: StoreError) -> Self {
        Self {
            result: Err(error),
            sequence: 0,
            digest: None,
            logical_time: None,
            raft_log_index: 0,
        }
    }
}

/// Typed in-process envelope used before conversion to the shared bounded wire
/// request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsensusRpc<T> {
    /// Exact consensus schema.
    pub schema_version: u16,
    /// Cluster/configuration/epoch scope.
    pub identity: SessionConsensusIdentity,
    /// Canonical sender ordinal.
    pub sender: SessionConsensusNodeId,
    /// Private engine RPC or SDK-owned forwarded request.
    pub payload: T,
}

impl<T> fmt::Debug for SessionConsensusRpc<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsensusRpc(<redacted>)")
    }
}

impl<T> SessionConsensusRpc<T> {
    /// Bind a payload to the current consensus scope.
    pub const fn new(
        identity: SessionConsensusIdentity,
        sender: SessionConsensusNodeId,
        payload: T,
    ) -> Self {
        Self {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            sender,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::Duration;

    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::SigningKey;

    use super::*;
    use crate::fenced_mutation_roster::{
        AdmissionProposal, EstablishedMutation, Member, MemberOperationId, Phase, Profile,
        RequestId, RosterAttestationCertificateRoleV1, RosterAttestationLeafCertificatePartsV1,
        RosterAttestationLeafCertificateV1, RosterAttestationTrustRootV1,
        RosterCompactAdmissionProvenanceSigningInputV2, RosterCompactTerminalEvidenceBindingV2,
        RosterCompactTerminalEvidenceV2, RosterCompactTerminalMemberProjectionV2,
        RosterCompactTerminalMemberProofPartsV2, RosterCompactTerminalMemberSigningInputV2,
        RosterExecutorMemberProofPartsV1, RosterId, RosterIngressAttestationSigningInputV1,
        RosterProviderOperationV1, RosterProviderOutcomeV1, Scope, TerminalRecord,
        FRESH_ROSTER_MEMBERS,
    };
    use crate::fenced_mutation_roster_executor::{AuthorityBinding, BackendRegistration};
    use crate::{
        EncryptedSessionPayload, FenceToken, FencedTransitionLease, FencedTransitionMutation,
        FencedTransitionMutationResult, FencedTransitionRequestId, FencedTransitionV2CallerNonce,
        Generation, OwnerId, SessionKeyType, StableId, StateClass, StateType, STABLE_ID_MAX_BYTES,
    };

    #[derive(Clone, Serialize, Deserialize)]
    enum LegacySessionMutationIntent684 {
        AdvanceLogicalTime,
        CompareAndSet(Box<CompareAndSet>),
        DeleteFenced(LeaseGuard),
        RefreshTtl {
            lease: LeaseGuard,
            ttl: Duration,
        },
        AcquireLease {
            key: SessionKey,
            owner: OwnerId,
            ttl: Duration,
        },
        RenewLease {
            lease: LeaseGuard,
            ttl: Duration,
        },
        ReleaseLease(LeaseGuard),
        BindConsumerRequest {
            request_commitment: [u8; 32],
        },
        ReadConsumerRecord {
            key: SessionKey,
        },
        FinalizeOperatorRecovery {
            recovery_epoch: u64,
            plan_digest: [u8; 32],
            fence_high_water: u64,
            credential_high_water: u64,
        },
        PrepareTopologyTransition {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
            desired_identity: SessionConsensusIdentity,
            desired_members: BTreeSet<SessionConsensusNodeId>,
            desired_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
        },
        MarkTopologyLearnersReady {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
        },
        FenceTopologyAuthority {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
        },
        AbortTopologyTransition {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
        },
        FinalizeTopologyTransition {
            transition_id: [u8; 16],
            request_digest: [u8; 32],
        },
        Authorized {
            origin: SessionConsensusNodeId,
            authority_identity: SessionConsensusIdentity,
            mutation: Box<LegacySessionMutationIntent684>,
        },
        FencedTransition(Box<FencedTransitionRequest>),
        ActivateFencedTransition {
            request: Box<FencedTransitionRequest>,
            scope_identity: SessionConsensusIdentity,
            voter_set_digest: [u8; 32],
        },
    }

    #[derive(Clone, Serialize, Deserialize)]
    enum LegacySessionMutationOutcome684 {
        CompareAndSet(CompareAndSetResult),
        ConsumerRecord(Option<StoredSessionRecord>),
        Lease(LeaseGuard),
        Unit,
        FencedTransition(FencedTransitionOutcome),
    }

    fn assert_postcard_cross_decode<T, U>(label: &str, current: T, legacy: U)
    where
        T: Serialize + DeserializeOwned,
        U: Serialize + DeserializeOwned,
    {
        let current_bytes =
            opc_consensus::encode_bounded(&current).expect("current postcard encoding");
        let legacy_bytes =
            opc_consensus::encode_bounded(&legacy).expect("legacy postcard encoding");
        assert_eq!(current_bytes, legacy_bytes, "{label}: encoding changed");
        opc_consensus::decode_bounded::<U>(&current_bytes).expect("legacy decode of current bytes");
        opc_consensus::decode_bounded::<T>(&legacy_bytes).expect("current decode of legacy bytes");
    }

    fn legacy_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("legacy-postcard"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"legacy-key")).expect("stable ID"),
        }
    }

    fn legacy_time(seconds: i64) -> opc_types::Timestamp {
        opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(seconds),
        )
    }

    fn legacy_lease(key: SessionKey, owner: OwnerId) -> LeaseGuard {
        LeaseGuard::new(
            key,
            owner,
            FenceToken::new(7),
            legacy_time(1),
            legacy_time(61),
            9,
        )
    }

    fn legacy_record(key: SessionKey, owner: OwnerId) -> StoredSessionRecord {
        StoredSessionRecord {
            key,
            generation: Generation::new(3),
            owner,
            fence: FenceToken::new(7),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("legacy-state"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"legacy-payload"),
        }
    }

    fn roster_digest_admission(plan_byte: u8) -> Admission {
        let proposal = AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([0x71; 16]).expect("roster ID"),
            (0..FRESH_ROSTER_MEMBERS)
                .map(|ordinal| {
                    Member::new(
                        ordinal as u8,
                        MemberOperationId::from_bytes([ordinal as u8 + 1; 16])
                            .expect("member operation ID"),
                        vec![ordinal as u8 + 1],
                        1,
                    )
                    .expect("member")
                })
                .collect(),
            EstablishedMutation::no_op(),
            vec![plan_byte],
            vec![0x73],
            vec![0x74],
        )
        .expect("admission proposal");
        Admission::authenticate(
            proposal,
            SessionKey {
                tenant: TenantId::from_static("roster-digest-tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: StableId::new(Bytes::from_static(b"roster-digest-key"))
                    .expect("stable ID"),
            },
            Scope::from_digest([0x75; 32]),
            OwnerId::new("roster-original-owner").expect("owner"),
            FenceToken::new(7),
            Generation::new(3),
        )
        .expect("authenticated admission")
    }

    fn roster_digest_authority(
        admission: &Admission,
        credential_id: u64,
        acquired_at: i64,
        expires_at: i64,
    ) -> AuthorityBinding {
        AuthorityBinding::from_consensus_parts(
            admission.scope().digest(),
            admission.key().clone(),
            admission.logical_owner().clone(),
            admission.admission_fence(),
            AuthorityLeaseMetadata::new(
                credential_id,
                admission.expected_generation(),
                legacy_time(acquired_at),
                legacy_time(expires_at),
            ),
        )
        .expect("authority")
    }

    fn compressed_key(key: &p256::ecdsa::VerifyingKey) -> [u8; 33] {
        key.to_sec1_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed P-256 key")
    }

    fn sign_digest(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
        let signature: p256::ecdsa::Signature = key.sign_prehash(&digest).expect("sign digest");
        signature.normalize_s().to_bytes().into()
    }

    fn roster_test_proof_bundle(admission: &Admission) -> RosterExecutorProofBundleV1 {
        roster_test_proof_bundle_with_evidence_prefix(admission, 0x84)
    }

    fn roster_test_proof_bundle_with_evidence_prefix(
        admission: &Admission,
        evidence_prefix: u8,
    ) -> RosterExecutorProofBundleV1 {
        let root_key = SigningKey::from_bytes((&[0x31; 32]).into()).expect("root key");
        let leaf_key = SigningKey::from_bytes((&[0x32; 32]).into()).expect("leaf key");
        let root =
            RosterAttestationTrustRootV1::new([0x81; 32], compressed_key(root_key.verifying_key()))
                .expect("test root");
        let mut certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role: RosterAttestationCertificateRoleV1::Executor,
            configuration_identity: legacy_identity(),
            scope: admission.scope().digest(),
            subject_identity_commitment: [0x82; 32],
            leaf_epoch: 1,
            key_id: [0x83; 32],
            not_before: legacy_time(1),
            not_after: legacy_time(61),
            public_key: compressed_key(leaf_key.verifying_key()),
            root_signature: [0; 64],
        };
        certificate.root_signature = sign_digest(
            &root_key,
            RosterExecutorProofBundleV1::certificate_signing_digest(&certificate)
                .expect("certificate digest"),
        );
        let mut provider_certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role: RosterAttestationCertificateRoleV1::Provider,
            configuration_identity: legacy_identity(),
            scope: admission.scope().digest(),
            subject_identity_commitment: [0x85; 32],
            leaf_epoch: 1,
            key_id: [0x86; 32],
            not_before: legacy_time(1),
            not_after: legacy_time(61),
            public_key: compressed_key(leaf_key.verifying_key()),
            root_signature: [0; 64],
        };
        provider_certificate.root_signature = sign_digest(
            &root_key,
            RosterExecutorProofBundleV1::certificate_signing_digest(&provider_certificate)
                .expect("provider certificate digest"),
        );
        let proofs = admission
            .members()
            .iter()
            .map(|member| RosterExecutorMemberProofPartsV1 {
                ordinal: member.ordinal(),
                provider_operation: RosterProviderOperationV1::Execute,
                outcome: RosterProviderOutcomeV1::AppliedExecuted,
                proof_epoch: 1,
                evidence: vec![evidence_prefix, member.ordinal()],
                provider_certificate: provider_certificate.clone(),
                provider_signature: sign_digest(
                    &leaf_key,
                    [member.ordinal().saturating_add(2); 32],
                ),
                signature: sign_digest(&leaf_key, [member.ordinal().saturating_add(1); 32]),
            })
            .collect();
        RosterExecutorProofBundleV1::issue_from_signed_parts(&root, certificate, proofs)
            .expect("structurally valid proof bundle")
    }

    struct RosterTestCertificateInput<'a> {
        role: RosterAttestationCertificateRoleV1,
        identity: SessionConsensusIdentity,
        scope: [u8; 32],
        subject_identity_commitment: [u8; 32],
        key_id: [u8; 32],
        public_key: &'a p256::ecdsa::VerifyingKey,
    }

    fn roster_test_certificate(
        root: &RosterAttestationTrustRootV1,
        root_key: &SigningKey,
        input: RosterTestCertificateInput<'_>,
    ) -> RosterAttestationLeafCertificatePartsV1 {
        let RosterTestCertificateInput {
            role,
            identity,
            scope,
            subject_identity_commitment,
            key_id,
            public_key,
        } = input;
        let mut certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role,
            configuration_identity: identity,
            scope,
            subject_identity_commitment,
            leaf_epoch: 1,
            key_id,
            not_before: legacy_time(1),
            not_after: legacy_time(61),
            public_key: compressed_key(public_key),
            root_signature: [0; 64],
        };
        certificate.root_signature = sign_digest(
            root_key,
            RosterAttestationLeafCertificateV1::signing_digest(&certificate)
                .expect("certificate digest"),
        );
        certificate
    }

    fn roster_production_admission_command(
        admission: Admission,
        authority: AuthorityBinding,
    ) -> ConsensusRosterAdmissionCommand {
        roster_production_admission_command_with_ingress_request_id(
            admission, authority, [0x45; 16],
        )
    }

    fn roster_production_admission_command_with_ingress_request_id(
        admission: Admission,
        authority: AuthorityBinding,
        ingress_request_id: [u8; 16],
    ) -> ConsensusRosterAdmissionCommand {
        let root_key = SigningKey::from_bytes((&[0x41; 32]).into()).expect("root key");
        let ingress_key = SigningKey::from_bytes((&[0x42; 32]).into()).expect("ingress key");
        let root =
            RosterAttestationTrustRootV1::new([0x43; 32], compressed_key(root_key.verifying_key()))
                .expect("trust root");
        let ingress_input = RosterIngressAttestationSigningInputV1 {
            peer_identity_commitment: [0x44; 32],
            consumer_scope: admission.scope().digest(),
            request_id: ingress_request_id,
            operation_tag: 1,
            canonical_capsule_digest: [0x46; 32],
            authenticated_at: legacy_time(2),
            peer_certificate_expires_at: legacy_time(61),
            material_generation: 1,
            handshake_epoch: 1,
        };
        let ingress = RosterIngressAttestationV1::issue_from_signed_parts(
            &root,
            roster_test_certificate(
                &root,
                &root_key,
                RosterTestCertificateInput {
                    role: RosterAttestationCertificateRoleV1::TransportIngress,
                    identity: legacy_identity(),
                    scope: admission.scope().digest(),
                    subject_identity_commitment: ingress_input.peer_identity_commitment,
                    key_id: [0x47; 32],
                    public_key: ingress_key.verifying_key(),
                },
            ),
            &ingress_input,
            sign_digest(
                &ingress_key,
                ingress_input.digest().expect("ingress digest"),
            ),
        )
        .expect("signed ingress");
        let provenance_input = RosterCompactAdmissionProvenanceSigningInputV2::for_admission(
            legacy_identity(),
            &admission,
            &authority,
            ingress.signing_input(),
            [0x48; 32],
        )
        .expect("provenance input");
        let provenance = RosterCompactAdmissionProvenanceV2::issue_from_signed_parts(
            &root,
            roster_test_certificate(
                &root,
                &root_key,
                RosterTestCertificateInput {
                    role: RosterAttestationCertificateRoleV1::TransportIngress,
                    identity: legacy_identity(),
                    scope: admission.scope().digest(),
                    subject_identity_commitment: [0x48; 32],
                    key_id: [0x49; 32],
                    public_key: ingress_key.verifying_key(),
                },
            ),
            &provenance_input,
            sign_digest(
                &ingress_key,
                provenance_input.digest().expect("provenance digest"),
            ),
        )
        .expect("signed provenance");
        ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id(
            admission,
            authority,
            ingress_input.request_id,
            ingress,
            provenance,
        )
        .expect("production admission command")
    }

    fn roster_production_terminal_command(
        admission: &Admission,
        authority: AuthorityBinding,
    ) -> ConsensusRosterTerminalCommand {
        roster_production_terminal_command_with_terminal_evidence_key_id(
            admission, authority, [0x5e; 32],
        )
    }

    fn roster_production_terminal_command_with_terminal_evidence_key_id(
        admission: &Admission,
        authority: AuthorityBinding,
        terminal_evidence_key_id: [u8; 32],
    ) -> ConsensusRosterTerminalCommand {
        let root_key = SigningKey::from_bytes((&[0x51; 32]).into()).expect("root key");
        let ingress_key = SigningKey::from_bytes((&[0x52; 32]).into()).expect("ingress key");
        let executor_key = SigningKey::from_bytes((&[0x53; 32]).into()).expect("executor key");
        let root =
            RosterAttestationTrustRootV1::new([0x54; 32], compressed_key(root_key.verifying_key()))
                .expect("trust root");
        let ingress_input = RosterIngressAttestationSigningInputV1 {
            peer_identity_commitment: [0x55; 32],
            consumer_scope: admission.scope().digest(),
            request_id: [0x56; 16],
            operation_tag: 2,
            canonical_capsule_digest: [0x57; 32],
            authenticated_at: legacy_time(2),
            peer_certificate_expires_at: legacy_time(61),
            material_generation: 1,
            handshake_epoch: 1,
        };
        let ingress = RosterIngressAttestationV1::issue_from_signed_parts(
            &root,
            roster_test_certificate(
                &root,
                &root_key,
                RosterTestCertificateInput {
                    role: RosterAttestationCertificateRoleV1::TransportIngress,
                    identity: legacy_identity(),
                    scope: admission.scope().digest(),
                    subject_identity_commitment: ingress_input.peer_identity_commitment,
                    key_id: [0x58; 32],
                    public_key: ingress_key.verifying_key(),
                },
            ),
            &ingress_input,
            sign_digest(
                &ingress_key,
                ingress_input.digest().expect("ingress digest"),
            ),
        )
        .expect("signed ingress");
        let provenance_input = RosterCompactAdmissionProvenanceSigningInputV2::for_admission(
            legacy_identity(),
            admission,
            &authority,
            ingress.signing_input(),
            [0x59; 32],
        )
        .expect("provenance input");
        let provenance = RosterCompactAdmissionProvenanceV2::issue_from_signed_parts(
            &root,
            roster_test_certificate(
                &root,
                &root_key,
                RosterTestCertificateInput {
                    role: RosterAttestationCertificateRoleV1::TransportIngress,
                    identity: legacy_identity(),
                    scope: admission.scope().digest(),
                    subject_identity_commitment: [0x59; 32],
                    key_id: [0x5a; 32],
                    public_key: ingress_key.verifying_key(),
                },
            ),
            &provenance_input,
            sign_digest(
                &ingress_key,
                provenance_input.digest().expect("provenance digest"),
            ),
        )
        .expect("signed provenance");
        let binding = admission.binding_key(9).expect("binding");
        let request_id = RequestId::bind(9, admission).expect("request ID");
        let registration =
            BackendRegistration::from_consensus_parts([0x5b; 32], request_id, admission)
                .expect("registration");
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            registration.consensus_parts();
        let evidence = vec![0x5c; 2];
        let commitments = admission
            .members()
            .iter()
            .map(|member| {
                crate::fenced_mutation_roster::stable_terminal_proof_commitment(
                    binding,
                    registration,
                    admission,
                    Phase::Established,
                    member,
                    RosterProviderOutcomeV1::AppliedExecuted,
                    crate::fenced_mutation_roster::roster_executor_evidence_commitment(&evidence),
                )
                .expect("terminal commitment")
            })
            .collect();
        let terminal = TerminalRecord::new(
            admission,
            registration_request_id,
            Phase::Established,
            commitments,
        )
        .expect("terminal");
        let terminal_binding = RosterCompactTerminalEvidenceBindingV2::for_terminal(
            legacy_identity(),
            binding,
            registration,
            &provenance,
            admission,
            &authority,
            &terminal,
            [0x5d; 32],
        )
        .expect("terminal evidence binding");
        let compact_proofs = admission
            .members()
            .iter()
            .zip(terminal.proof_commitments())
            .map(|(member, stable_proof_commitment)| {
                let member = RosterCompactTerminalMemberProjectionV2 {
                    ordinal: member.ordinal(),
                    member_operation_id: *member.operation_id().as_bytes(),
                    descriptor_length: member.descriptor().len() as u16,
                    descriptor_commitment: member.descriptor_commitment(),
                    expected_member_version: member.expected_version(),
                    admission_generation: admission.expected_generation().get(),
                    proof_epoch: 1,
                    provider_operation: RosterProviderOperationV1::Execute,
                    outcome: RosterProviderOutcomeV1::AppliedExecuted,
                    evidence_length: evidence.len() as u16,
                    evidence_commitment:
                        crate::fenced_mutation_roster::roster_executor_evidence_commitment(
                            &evidence,
                        ),
                    stable_proof_commitment: *stable_proof_commitment,
                };
                let provider_certificate = roster_test_certificate(
                    &root,
                    &root_key,
                    RosterTestCertificateInput {
                        role: RosterAttestationCertificateRoleV1::Provider,
                        identity: legacy_identity(),
                        scope: admission.scope().digest(),
                        subject_identity_commitment: [0x5e; 32],
                        key_id: [0x60; 32],
                        public_key: executor_key.verifying_key(),
                    },
                );
                let provider = RosterAttestationLeafCertificateV1::issue_from_signed_parts(
                    &root,
                    provider_certificate.clone(),
                )
                .expect("provider certificate");
                RosterCompactTerminalMemberProofPartsV2 {
                    provider_signature: sign_digest(
                        &executor_key,
                        crate::fenced_mutation_roster::provider_receipt_compact_digest(
                            &terminal_binding,
                            &member,
                            &provider,
                        )
                        .expect("provider compact digest"),
                    ),
                    provider_certificate,
                    signature: sign_digest(
                        &executor_key,
                        RosterCompactTerminalMemberSigningInputV2 {
                            binding: terminal_binding.clone(),
                            member: member.clone(),
                        }
                        .digest()
                        .expect("compact proof digest"),
                    ),
                    member,
                }
            })
            .collect();
        let terminal_evidence = RosterCompactTerminalEvidenceV2::issue_from_signed_parts(
            &root,
            roster_test_certificate(
                &root,
                &root_key,
                RosterTestCertificateInput {
                    role: RosterAttestationCertificateRoleV1::Executor,
                    identity: legacy_identity(),
                    scope: admission.scope().digest(),
                    subject_identity_commitment: [0x5d; 32],
                    key_id: terminal_evidence_key_id,
                    public_key: executor_key.verifying_key(),
                },
            ),
            &terminal_binding,
            compact_proofs,
        )
        .expect("signed terminal evidence");
        ConsensusRosterTerminalCommand::new_with_proof_bundle_evidence_and_ingress_request_id(
            ConsensusRosterTerminalCommandInput {
                binding,
                registration_handle,
                registration_request_id,
                registration_terminal_slot: *registration_terminal_slot.as_bytes(),
                authority,
                record: terminal
                    .to_canonical_bytes(admission)
                    .expect("terminal bytes"),
            },
            roster_test_proof_bundle(admission),
            terminal_evidence,
            ingress_input.request_id,
            ingress,
        )
        .expect("production terminal command")
    }

    fn roster_terminal_command(
        admission: &Admission,
        input: ConsensusRosterTerminalCommandInput,
    ) -> ConsensusRosterTerminalCommand {
        ConsensusRosterTerminalCommand::new_with_proof_bundle(
            input,
            roster_test_proof_bundle(admission),
        )
        .expect("terminal command")
    }

    fn legacy_identity() -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            SessionConsensusClusterId::new("legacy-cluster").expect("cluster"),
            SessionConsensusConfigurationId::from_bytes([0x41; 32]),
            SessionConsensusConfigurationEpoch::new(2).expect("epoch"),
        )
    }

    fn v2_digest_command(intent: SessionMutationIntent) -> SessionConsensusCommand {
        SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: legacy_identity(),
            request_id: SessionConsensusRequestId::from_bytes([0xD1; 16]),
            logical_time: legacy_time(37),
            intent,
        }
    }

    fn v2_digest_request() -> FencedTransitionV2Request {
        let key = legacy_key();
        let owner = OwnerId::new("v2-digest-owner").expect("owner");
        FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0xD2; 16]),
            FencedTransitionLease::acquire(key, owner, FenceToken::new(0), Duration::from_secs(60))
                .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("V2 request")
    }

    fn v2_digest_variant_requests() -> [FencedTransitionV2Request; 4] {
        let key = legacy_key();
        let owner = OwnerId::new("v2-digest-owner").expect("owner");
        let record = |generation, payload| StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(generation),
            owner: owner.clone(),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("v2-digest"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(payload),
        };
        let renew_guard = LeaseGuard::new(
            key.clone(),
            owner.clone(),
            FenceToken::new(1),
            legacy_time(1),
            legacy_time(61),
            2,
        );
        [
            FencedTransitionV2Request::new(
                FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                FencedTransitionV2CallerNonce::from_bytes([0xD6; 16]),
                FencedTransitionLease::acquire(
                    key.clone(),
                    owner.clone(),
                    FenceToken::new(0),
                    Duration::from_secs(60),
                )
                .expect("acquire"),
                FencedTransitionMutation::create(record(1, b"create")),
            )
            .expect("create request"),
            FencedTransitionV2Request::new(
                FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                FencedTransitionV2CallerNonce::from_bytes([0xD7; 16]),
                FencedTransitionLease::renew(renew_guard.clone(), Duration::from_secs(60))
                    .expect("renew"),
                FencedTransitionMutation::update(Generation::new(1), record(2, b"update")),
            )
            .expect("update request"),
            FencedTransitionV2Request::new(
                FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                FencedTransitionV2CallerNonce::from_bytes([0xD8; 16]),
                FencedTransitionLease::renew(renew_guard.clone(), Duration::from_secs(60))
                    .expect("renew"),
                FencedTransitionMutation::delete(Generation::new(1)),
            )
            .expect("delete request"),
            FencedTransitionV2Request::new(
                FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                FencedTransitionV2CallerNonce::from_bytes([0xD9; 16]),
                FencedTransitionLease::renew(renew_guard, Duration::from_secs(60)).expect("renew"),
                FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(20))
                    .expect("refresh"),
            )
            .expect("refresh request"),
        ]
    }

    #[test]
    fn v2_batch_validation_binds_ordered_full_ids_and_one_epoch() {
        let [first, second, ..] = v2_digest_variant_requests();
        assert!(validate_fenced_transition_v2_batch(&[first.clone(), second.clone()]).is_ok());
        assert!(validate_fenced_transition_v2_batch(&[]).is_err());
        assert!(validate_fenced_transition_v2_batch(&[first.clone(), first.clone()]).is_err());

        let mismatched_epoch = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(8).expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0xDA; 16]),
            second.lease().clone(),
            second.mutation().clone(),
        )
        .expect("different epoch request");
        assert!(validate_fenced_transition_v2_batch(&[first.clone(), mismatched_epoch]).is_err());

        let first_outer =
            fenced_transition_v2_batch_outer_request_id(&[first.clone(), second.clone()])
                .expect("batch outer ID");
        assert_eq!(
            first_outer,
            fenced_transition_v2_batch_outer_request_id(&[first.clone(), second.clone()])
                .expect("stable batch outer ID")
        );
        assert_ne!(
            first_outer,
            fenced_transition_v2_batch_outer_request_id(&[second, first])
                .expect("reordered batch outer ID"),
            "ordered full IDs, rather than a set, define the durable batch identity"
        );
    }

    #[test]
    fn v2_batch_intent_uses_a_fixed_full_id_digest_shape() {
        let [first, second, ..] = v2_digest_variant_requests();
        let command = v2_digest_command(SessionMutationIntent::FencedTransitionV2Batch(vec![
            first.clone(),
            second.clone(),
        ]));
        let encoded = command
            .encode_v2_applied_digest_input(
                5,
                SessionConsensusEntryDigest::from_bytes([0xD3; 32]),
                legacy_time(41),
            )
            .expect("batch digest encoding");
        let suffix = &encoded[encoded.len() - (1 + 2 + (2 * 56))..];
        assert_eq!(suffix[0], 5, "V2 batch applied-digest tag");
        assert_eq!(&suffix[1..3], &2_u16.to_be_bytes());
        assert_eq!(&suffix[3..59], &first.request_id().to_bytes());
        assert_eq!(&suffix[59..115], &second.request_id().to_bytes());

        let outcomes = vec![Err(StoreError::LeaseHeld), Err(StoreError::LeaseExpired)];
        assert!(validate_fenced_transition_v2_batch_outcomes(&outcomes).is_ok());
        let outcome = SessionMutationOutcome::FencedTransitionV2Batch(outcomes);
        assert!(opc_consensus::encode_bounded(&outcome).is_ok());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn v2_applied_digest_uses_fixed_golden_encoding_for_each_intent_shape() {
        let previous = SessionConsensusEntryDigest::from_bytes([0xD3; 32]);
        let effective = legacy_time(41);
        let request = v2_digest_request();
        let identity = legacy_identity();
        let commands = [
            v2_digest_command(SessionMutationIntent::FencedTransitionV2(Box::new(
                request.clone(),
            ))),
            v2_digest_command(SessionMutationIntent::ActivateFencedTransitionV2 {
                request: Box::new(request.clone()),
                scope_identity: identity,
                voter_set_digest: [0xD4; 32],
                profile_digest: [0xD5; 32],
            }),
            v2_digest_command(SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: 11,
                expected_active_epoch: Some(FencedTransitionV2HistoryEpoch::new(7).expect("epoch")),
                expected_retired_through: 6,
                expected_bound_entries: 23,
            }),
            v2_digest_command(SessionMutationIntent::Authorized {
                origin: SessionConsensusNodeId::new(9).expect("origin"),
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::FencedTransitionV2(Box::new(request))),
            }),
        ];
        let expected_digests = [
            "2da22c549efc00b3757fd393a6afd6eaeb58f26b92a63e2393fe47e92ade8be7",
            "0486c039d926654753bf5641cb55c345813212a1df3371f0338822c9e65cccc4",
            "137599aca38dbb4142f99d49016f80dc2b27d2930026d25096adeaa0a062f067",
            "34aaad50947be0d34959ebf15b900bfbc86f966ed378a99f5c5897a79124734d",
        ];
        for (index, (command, expected_digest)) in commands.iter().zip(expected_digests).enumerate()
        {
            let encoded = command
                .encode_v2_applied_digest_input(5, previous, effective)
                .expect("fixed V2 digest encoding");
            let digest = command
                .calculate_applied_digest(5, previous, effective)
                .expect("V2 digest");
            assert!(encoded.starts_with(COMMAND_V2_DIGEST_MAGIC));
            assert_eq!(
                hex(digest.as_bytes()),
                expected_digest,
                "V2 applied digest golden shape {index}"
            );
        }
    }

    #[test]
    fn v2_applied_digest_is_domain_separated_and_rejects_non_v2_inner_intent() {
        let previous = SessionConsensusEntryDigest::from_bytes([0xD3; 32]);
        let effective = legacy_time(41);
        let legacy = v2_digest_command(SessionMutationIntent::AdvanceLogicalTime);
        let legacy_encoded =
            serde_json::to_vec(&(5_u64, previous, effective, &legacy)).expect("legacy JSON");
        let mut legacy_hasher = Sha256::new();
        legacy_hasher.update(COMMAND_DIGEST_DOMAIN);
        legacy_hasher.update(legacy_encoded);
        assert_eq!(
            legacy.calculate_applied_digest(5, previous, effective),
            Ok(SessionConsensusEntryDigest::from_bytes(
                legacy_hasher.finalize().into()
            )),
            "non-V2 command digest remains byte-for-byte V1 JSON"
        );
        let non_v2_authorized = SessionMutationIntent::Authorized {
            origin: SessionConsensusNodeId::new(9).expect("origin"),
            authority_identity: legacy_identity(),
            mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
        };
        let mut malformed = Vec::new();
        assert!(matches!(
            append_v2_applied_intent(&mut malformed, &non_v2_authorized),
            Err(StoreError::Serialization(_))
        ));
    }

    #[test]
    fn v2_command_json_log_wire_is_pinned() {
        let request = v2_digest_request();
        let identity = legacy_identity();
        let commands = [
            v2_digest_command(SessionMutationIntent::FencedTransitionV2(Box::new(
                request.clone(),
            ))),
            v2_digest_command(SessionMutationIntent::ActivateFencedTransitionV2 {
                request: Box::new(request.clone()),
                scope_identity: identity,
                voter_set_digest: [0xD4; 32],
                profile_digest: [0xD5; 32],
            }),
            v2_digest_command(SessionMutationIntent::Authorized {
                origin: SessionConsensusNodeId::new(9).expect("origin"),
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::ActivateFencedTransitionV2 {
                    request: Box::new(request),
                    scope_identity: identity,
                    voter_set_digest: [0xD4; 32],
                    profile_digest: [0xD5; 32],
                }),
            }),
            v2_digest_command(SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: 11,
                expected_active_epoch: Some(FencedTransitionV2HistoryEpoch::new(7).expect("epoch")),
                expected_retired_through: 6,
                expected_bound_entries: 23,
            }),
        ];
        let expected_hashes = [
            "1c5fcc60eca9d4b0de38c83442695b63b2693ab5eab24d6ce8ac78481fae011f",
            "4961aaad86f407d643818d5fb963a62372ce167c1aeaa47b0f45a9dc792a7f63",
            "eaf23c0230cffc5b3a3c62fa949a1fb3e90904dd589e4d2b09dc694ec0e2e746",
            "4983e341ace6866148883f4c64921a2a1f252e4468a61ddd4a5da02aadff1a7d",
        ];
        for (index, (command, expected_hash)) in commands.iter().zip(expected_hashes).enumerate() {
            let encoded = serde_json::to_vec(command).expect("V2 log JSON");
            assert_eq!(
                hex(&Sha256::digest(encoded)),
                expected_hash,
                "V2 durable-log JSON {index}"
            );
        }
    }

    #[test]
    fn v2_request_variant_postcard_and_json_wire_hashes_are_pinned() {
        let expected_postcard_hashes = [
            "70b226d2cd91eb9d586181053af8489132ddf4f6810811b693034f6bb9e46015",
            "226aff8df1e01e92a1a3cef0c3388bdfb9cb381d7dba1faad7ca554d84cc8f37",
            "c0b046501b7a10a1a817e332ae36f0d8b67378077859c22c5ef339bea83a87d4",
            "37796b2b363700ac9200dbddb49436d9757dbe69dcd66e10ae142fca4fc65b9f",
        ];
        let expected_json_hashes = [
            "768ddb1eb21a40e9b6a3c46e1cfc29768be38311f05f1674205365fa5ac52499",
            "da789ecbab52199cf546b2150222dd03cd3e05b97e9a0656b6dcce1e979f97a2",
            "fa8b8ae5f5ca1b5dbf5ed14e7f12f8104ea9661f40b84038d96d9290de8db826",
            "e53aa37aafb7b5e100be93d0418b43b0b719b21098e723966dc7c9286a264dfd",
        ];
        for (index, ((request, expected_postcard_hash), expected_json_hash)) in
            v2_digest_variant_requests()
                .into_iter()
                .zip(expected_postcard_hashes)
                .zip(expected_json_hashes)
                .enumerate()
        {
            let command =
                v2_digest_command(SessionMutationIntent::FencedTransitionV2(Box::new(request)));
            let postcard = opc_consensus::encode_bounded(&command).expect("postcard");
            let json = serde_json::to_vec(&command).expect("JSON");
            assert_eq!(
                hex(&Sha256::digest(postcard)),
                expected_postcard_hash,
                "V2 peer/Raft postcard request shape {index}",
            );
            assert_eq!(
                hex(&Sha256::digest(json)),
                expected_json_hash,
                "V2 durable-log JSON request shape {index}",
            );
        }
    }

    #[test]
    fn v2_command_postcard_wire_ordinals_are_pinned() {
        let request = v2_digest_request();
        let identity = legacy_identity();
        let commands = [
            v2_digest_command(SessionMutationIntent::FencedTransitionV2(Box::new(
                request.clone(),
            ))),
            v2_digest_command(SessionMutationIntent::ActivateFencedTransitionV2 {
                request: Box::new(request.clone()),
                scope_identity: identity,
                voter_set_digest: [0xD4; 32],
                profile_digest: [0xD5; 32],
            }),
            v2_digest_command(SessionMutationIntent::Authorized {
                origin: SessionConsensusNodeId::new(9).expect("origin"),
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::ActivateFencedTransitionV2 {
                    request: Box::new(request),
                    scope_identity: identity,
                    voter_set_digest: [0xD4; 32],
                    profile_digest: [0xD5; 32],
                }),
            }),
            v2_digest_command(SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: 11,
                expected_active_epoch: Some(FencedTransitionV2HistoryEpoch::new(7).expect("epoch")),
                expected_retired_through: 6,
                expected_bound_entries: 23,
            }),
        ];
        let expected = [
            "01e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d114313937302d30312d30315430303a30303a33375a1207d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d22ef551462247eb23931fd020dfc974ff9ff0cfc495735cf66c5bbd98b2047482000f6c65676163792d706f73746361726403736d660b7064752d73657373696f6e0a6c65676163792d6b65790f76322d6469676573742d6f776e6572003c000201",
            "01e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d114313937302d30312d30315430303a30303a33375a1407d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d22ef551462247eb23931fd020dfc974ff9ff0cfc495735cf66c5bbd98b2047482000f6c65676163792d706f73746361726403736d660b7064752d73657373696f6e0a6c65676163792d6b65790f76322d6469676573742d6f776e6572003c000201e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5",
            "01e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d114313937302d30312d30315430303a30303a33375a0f09e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a383864141414141414141414141414141414141414141414141414141414141414141021407d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d22ef551462247eb23931fd020dfc974ff9ff0cfc495735cf66c5bbd98b2047482000f6c65676163792d706f73746361726403736d660b7064752d73657373696f6e0a6c65676163792d6b65790f76322d6469676573742d6f776e6572003c000201e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5",
            "01e2c92e0cc34ebcb7585b587d72901be80ccd59355253f8d91c570c1a51a38386414141414141414141414141414141414141414141414141414141414141414102d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d114313937302d30312d30315430303a30303a33375a150b01070617",
        ];
        let mut expected = expected.map(str::to_owned);
        expected[1] = expected[1].replacen("5a14", "5a13", 1);
        expected[2] = expected[2].replacen("0214", "0213", 1);
        expected[3] = expected[3].replacen("5a15", "5a14", 1);
        for (index, (command, expected)) in commands.iter().zip(expected).enumerate() {
            let encoded = opc_consensus::encode_bounded(command).expect("V2 command postcard");
            assert_eq!(hex(&encoded), expected, "V2 command postcard {index}");
        }
    }

    #[test]
    fn v2_command_postcard_wire_ordinals_match_the_frozen_descriptor() {
        let request = v2_digest_request();
        let identity = legacy_identity();
        let intents = [
            (
                "fenced-v2",
                18,
                SessionMutationIntent::FencedTransitionV2(Box::new(request.clone())),
            ),
            (
                "activate-v2",
                19,
                SessionMutationIntent::ActivateFencedTransitionV2 {
                    request: Box::new(request.clone()),
                    scope_identity: identity,
                    voter_set_digest: [0xD4; 32],
                    profile_digest: [0xD5; 32],
                },
            ),
            (
                "maintain-v2",
                20,
                SessionMutationIntent::MaintainFencedTransitionV2History {
                    expected_generation: 11,
                    expected_active_epoch: Some(
                        FencedTransitionV2HistoryEpoch::new(7).expect("epoch"),
                    ),
                    expected_retired_through: 6,
                    expected_bound_entries: 23,
                },
            ),
            (
                "fenced-v2-batch",
                21,
                SessionMutationIntent::FencedTransitionV2Batch(vec![request]),
            ),
        ];
        for (label, expected_tag, intent) in intents {
            let intent_bytes =
                opc_consensus::encode_bounded(&intent).expect("V2 intent postcard encoding");
            assert_eq!(
                intent_bytes.first().copied(),
                Some(expected_tag),
                "{label} Postcard discriminator must match the frozen V2 command wire descriptor",
            );

            let command = v2_digest_command(intent);
            let command_bytes =
                opc_consensus::encode_bounded(&command).expect("V2 command postcard encoding");
            assert!(command_bytes.ends_with(&intent_bytes));
            assert_eq!(
                &command_bytes[command_bytes.len() - intent_bytes.len()..],
                intent_bytes.as_slice(),
                "{label} must retain its exact intent bytes in the replicated command",
            );
        }
    }

    #[test]
    fn schema_v1_legacy_intent_and_outcome_postcard_parity() {
        let key = legacy_key();
        let owner = OwnerId::new("legacy-owner").expect("owner");
        let lease = legacy_lease(key.clone(), owner.clone());
        let record = legacy_record(key.clone(), owner.clone());
        let cas = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(2)),
            new_record: record.clone(),
        };
        let identity = legacy_identity();
        let node = SessionConsensusNodeId::new(1).expect("node");
        let mut members = BTreeSet::new();
        members.insert(node);
        let mut bindings = BTreeMap::new();
        bindings.insert(
            node,
            SessionTopologyMemberBinding::new([1; 32], [2; 32], [3; 32], [4; 32]),
        );

        assert_postcard_cross_decode(
            "AdvanceLogicalTime",
            SessionMutationIntent::AdvanceLogicalTime,
            LegacySessionMutationIntent684::AdvanceLogicalTime,
        );
        assert_postcard_cross_decode(
            "CompareAndSet",
            SessionMutationIntent::CompareAndSet(Arc::new(cas.clone())),
            LegacySessionMutationIntent684::CompareAndSet(Box::new(cas)),
        );
        assert_postcard_cross_decode(
            "DeleteFenced",
            SessionMutationIntent::DeleteFenced(lease.clone()),
            LegacySessionMutationIntent684::DeleteFenced(lease.clone()),
        );
        assert_postcard_cross_decode(
            "RefreshTtl",
            SessionMutationIntent::RefreshTtl {
                lease: lease.clone(),
                ttl: Duration::from_secs(20),
            },
            LegacySessionMutationIntent684::RefreshTtl {
                lease: lease.clone(),
                ttl: Duration::from_secs(20),
            },
        );
        assert_postcard_cross_decode(
            "AcquireLease",
            SessionMutationIntent::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                ttl: Duration::from_secs(20),
            },
            LegacySessionMutationIntent684::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                ttl: Duration::from_secs(20),
            },
        );
        assert_postcard_cross_decode(
            "RenewLease",
            SessionMutationIntent::RenewLease {
                lease: lease.clone(),
                ttl: Duration::from_secs(20),
            },
            LegacySessionMutationIntent684::RenewLease {
                lease: lease.clone(),
                ttl: Duration::from_secs(20),
            },
        );
        assert_postcard_cross_decode(
            "ReleaseLease",
            SessionMutationIntent::ReleaseLease(lease.clone()),
            LegacySessionMutationIntent684::ReleaseLease(lease.clone()),
        );
        assert_postcard_cross_decode(
            "BindConsumerRequest",
            SessionMutationIntent::BindConsumerRequest {
                request_commitment: [5; 32],
            },
            LegacySessionMutationIntent684::BindConsumerRequest {
                request_commitment: [5; 32],
            },
        );
        assert_postcard_cross_decode(
            "ReadConsumerRecord",
            SessionMutationIntent::ReadConsumerRecord { key: key.clone() },
            LegacySessionMutationIntent684::ReadConsumerRecord { key: key.clone() },
        );
        assert_postcard_cross_decode(
            "FinalizeOperatorRecovery",
            SessionMutationIntent::FinalizeOperatorRecovery {
                recovery_epoch: 4,
                plan_digest: [6; 32],
                fence_high_water: 7,
                credential_high_water: 8,
            },
            LegacySessionMutationIntent684::FinalizeOperatorRecovery {
                recovery_epoch: 4,
                plan_digest: [6; 32],
                fence_high_water: 7,
                credential_high_water: 8,
            },
        );
        assert_postcard_cross_decode(
            "PrepareTopologyTransition",
            SessionMutationIntent::PrepareTopologyTransition {
                transition_id: [9; 16],
                request_digest: [10; 32],
                desired_identity: identity,
                desired_members: members.clone(),
                desired_bindings: bindings.clone(),
            },
            LegacySessionMutationIntent684::PrepareTopologyTransition {
                transition_id: [9; 16],
                request_digest: [10; 32],
                desired_identity: identity,
                desired_members: members,
                desired_bindings: bindings,
            },
        );
        assert_postcard_cross_decode(
            "MarkTopologyLearnersReady",
            SessionMutationIntent::MarkTopologyLearnersReady {
                transition_id: [11; 16],
                request_digest: [12; 32],
            },
            LegacySessionMutationIntent684::MarkTopologyLearnersReady {
                transition_id: [11; 16],
                request_digest: [12; 32],
            },
        );
        assert_postcard_cross_decode(
            "FenceTopologyAuthority",
            SessionMutationIntent::FenceTopologyAuthority {
                transition_id: [13; 16],
                request_digest: [14; 32],
            },
            LegacySessionMutationIntent684::FenceTopologyAuthority {
                transition_id: [13; 16],
                request_digest: [14; 32],
            },
        );
        assert_postcard_cross_decode(
            "AbortTopologyTransition",
            SessionMutationIntent::AbortTopologyTransition {
                transition_id: [15; 16],
                request_digest: [16; 32],
            },
            LegacySessionMutationIntent684::AbortTopologyTransition {
                transition_id: [15; 16],
                request_digest: [16; 32],
            },
        );
        assert_postcard_cross_decode(
            "FinalizeTopologyTransition",
            SessionMutationIntent::FinalizeTopologyTransition {
                transition_id: [17; 16],
                request_digest: [18; 32],
            },
            LegacySessionMutationIntent684::FinalizeTopologyTransition {
                transition_id: [17; 16],
                request_digest: [18; 32],
            },
        );
        assert_postcard_cross_decode(
            "Authorized",
            SessionMutationIntent::Authorized {
                origin: node,
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
            },
            LegacySessionMutationIntent684::Authorized {
                origin: node,
                authority_identity: identity,
                mutation: Box::new(LegacySessionMutationIntent684::AdvanceLogicalTime),
            },
        );
        let fenced_request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x31; 16]),
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(0),
                Duration::from_secs(20),
            )
            .expect("legacy fenced lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("legacy fenced request");
        assert_postcard_cross_decode(
            "FencedTransition",
            SessionMutationIntent::FencedTransition(Box::new(fenced_request.clone())),
            LegacySessionMutationIntent684::FencedTransition(Box::new(fenced_request.clone())),
        );
        assert_postcard_cross_decode(
            "ActivateFencedTransition",
            SessionMutationIntent::ActivateFencedTransition {
                request: Box::new(fenced_request.clone()),
                scope_identity: identity,
                voter_set_digest: [0x32; 32],
            },
            LegacySessionMutationIntent684::ActivateFencedTransition {
                request: Box::new(fenced_request),
                scope_identity: identity,
                voter_set_digest: [0x32; 32],
            },
        );

        assert_postcard_cross_decode(
            "Outcome::CompareAndSet",
            SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success),
            LegacySessionMutationOutcome684::CompareAndSet(CompareAndSetResult::Success),
        );
        assert_postcard_cross_decode(
            "Outcome::ConsumerRecord",
            SessionMutationOutcome::ConsumerRecord(None),
            LegacySessionMutationOutcome684::ConsumerRecord(None),
        );
        assert_postcard_cross_decode(
            "Outcome::Lease",
            SessionMutationOutcome::Lease(lease),
            LegacySessionMutationOutcome684::Lease(legacy_lease(key.clone(), owner.clone())),
        );
        assert_postcard_cross_decode(
            "Outcome::Unit",
            SessionMutationOutcome::Unit,
            LegacySessionMutationOutcome684::Unit,
        );
        let fenced_outcome = FencedTransitionOutcome::new(
            LeaseGuard::new(
                key,
                owner,
                FenceToken::new(1),
                legacy_time(3),
                legacy_time(23),
                1,
            ),
            Generation::new(1),
            FencedTransitionMutationResult::Deleted,
            legacy_time(3),
        )
        .expect("legacy fenced outcome");
        assert_postcard_cross_decode(
            "Outcome::FencedTransition",
            SessionMutationOutcome::FencedTransition(fenced_outcome.clone()),
            LegacySessionMutationOutcome684::FencedTransition(fenced_outcome),
        );
    }

    #[test]
    fn consensus_intent_serde_enforces_stable_id_before_admission() {
        let key = SessionKey {
            tenant: TenantId::from_static("consensus-stable-id-test"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from(vec![0xa5; STABLE_ID_MAX_BYTES]))
                .expect("maximum stable ID"),
        };
        let intent = SessionMutationIntent::AcquireLease {
            key,
            owner: OwnerId::new("owner-a").expect("owner"),
            ttl: Duration::from_secs(60),
        };
        let valid = serde_json::to_value(intent).expect("valid intent");

        for (width, accepted) in [
            (0, false),
            (1, true),
            (STABLE_ID_MAX_BYTES, true),
            (STABLE_ID_MAX_BYTES + 1, false),
        ] {
            let mut wire = valid.clone();
            wire["AcquireLease"]["key"]["stable_id"] = serde_json::json!(vec![0xa5_u8; width]);
            let decoded = serde_json::from_value::<SessionMutationIntent>(wire);
            assert_eq!(decoded.is_ok(), accepted, "stable ID width {width}");
            if let Err(error) = decoded {
                assert!(!error.to_string().contains("165"));
            }
        }
    }

    #[test]
    fn bounded_roster_capsule_enforces_maximum_before_retention() {
        assert!(BoundedRosterCapsule::<3>::new(vec![1, 2, 3]).is_ok());
        assert!(BoundedRosterCapsule::<3>::new(vec![1, 2, 3, 4]).is_err());
        assert!(
            serde_json::from_value::<BoundedRosterCapsule<3>>(serde_json::json!([1_u8, 2, 3]))
                .is_ok()
        );
        assert!(
            serde_json::from_value::<BoundedRosterCapsule<3>>(serde_json::json!([1_u8, 2, 3, 4]))
                .is_err()
        );
    }

    #[test]
    fn roster_admission_serialization_revalidates_canonical_body_and_authority() {
        let admission = roster_digest_admission(0x76);
        let authority = roster_digest_authority(&admission, 11, 1, 61);
        let command = roster_production_admission_command(admission, authority);
        let encoded = postcard::to_allocvec(&command).expect("admission wire");
        let decoded = postcard::from_bytes::<ConsensusRosterAdmissionCommand>(&encoded)
            .expect("validated admission wire");
        assert_eq!(
            encoded,
            postcard::to_allocvec(&decoded).expect("re-encoded admission wire"),
            "the non-wire digest cache must not alter admission command bytes"
        );
        assert_eq!(
            command.immutable_payload_digest().expect("digest"),
            decoded.immutable_payload_digest().expect("digest")
        );
        assert_eq!(
            command.exact_attempt_digest().expect("attempt digest"),
            decoded.exact_attempt_digest().expect("attempt digest"),
            "deserialization rebuilds, rather than trusts, the exact digest cache"
        );
        let malformed = ConsensusRosterAdmissionWire {
            admission: BoundedRosterCapsule::new(
                command
                    .admission()
                    .to_canonical_bytes()
                    .expect("canonical admission"),
            )
            .expect("bounded admission"),
            authority: command.authority().into(),
            ingress_request_id: [0x81; 16],
            ingress_attestation: BoundedRosterCapsule::new(Vec::new())
                .expect("empty compatibility ingress"),
            admission_provenance: BoundedRosterCapsule::new(Vec::new())
                .expect("empty compatibility provenance"),
        };
        let malformed = postcard::to_allocvec(&malformed).expect("malformed admission wire");
        assert!(postcard::from_bytes::<ConsensusRosterAdmissionCommand>(&malformed).is_err());
    }

    #[test]
    fn roster_admission_digest_conflicts_on_exact_body_or_original_provenance() {
        let admission = roster_digest_admission(0x76);
        let command = ConsensusRosterAdmissionCommand::new(
            admission.clone(),
            roster_digest_authority(&admission, 11, 1, 61),
        )
        .expect("admission command");
        let changed_provenance = ConsensusRosterAdmissionCommand::new(
            admission,
            roster_digest_authority(command.admission(), 12, 1, 61),
        )
        .expect("changed provenance");
        let changed_admission = roster_digest_admission(0x77);
        let changed_body = ConsensusRosterAdmissionCommand::new(
            changed_admission.clone(),
            roster_digest_authority(&changed_admission, 11, 1, 61),
        )
        .expect("changed body");

        assert_eq!(
            command.request_id().expect("request ID"),
            changed_body.request_id().expect("request ID")
        );
        assert_ne!(
            command.immutable_payload_digest().expect("digest"),
            changed_provenance
                .immutable_payload_digest()
                .expect("digest")
        );
        assert_ne!(
            command.immutable_payload_digest().expect("digest"),
            changed_body.immutable_payload_digest().expect("digest")
        );
    }

    #[test]
    fn roster_digest_caches_match_the_canonical_wire_references() {
        let admission = roster_digest_admission(0x76);
        let admission_command = roster_production_admission_command(
            admission.clone(),
            roster_digest_authority(&admission, 11, 1, 61),
        );
        let admission_bytes = admission_command
            .admission()
            .to_canonical_bytes()
            .expect("canonical admission");
        let admission_authority = roster_authority_canonical_bytes(admission_command.authority())
            .expect("canonical admission authority");
        assert_eq!(
            admission_command
                .immutable_payload_digest()
                .expect("cached admission digest"),
            roster_admission_immutable_payload_digest(&admission_bytes, &admission_authority),
            "the cached immutable admission digest retains its old canonical input"
        );
        assert_eq!(
            admission_command
                .exact_attempt_digest()
                .expect("cached admission attempt"),
            roster_command_attempt_digest_reference(1, &admission_command)
                .expect("canonical admission attempt"),
            "the cached admission attempt equals exact command Postcard bytes"
        );

        let terminal_command = roster_production_terminal_command(
            &admission,
            roster_digest_authority(&admission, 11, 1, 61),
        );
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            terminal_command.registration_parts();
        assert_eq!(
            terminal_command.immutable_payload_digest(),
            roster_terminal_immutable_payload_digest(
                terminal_command.binding(),
                registration_handle,
                registration_request_id,
                registration_terminal_slot,
                terminal_command.record_bytes(),
            ),
            "the cached immutable terminal digest retains its old canonical input"
        );
        assert_eq!(
            terminal_command
                .exact_attempt_digest()
                .expect("cached terminal attempt"),
            roster_command_attempt_digest_reference(2, &terminal_command)
                .expect("canonical terminal attempt"),
            "the cached terminal attempt equals exact command Postcard bytes"
        );
    }

    #[test]
    fn roster_applied_digest_binds_exact_inner_and_outer_command_shapes() {
        let admission = roster_digest_admission(0x76);
        let authority = roster_digest_authority(&admission, 11, 1, 61);
        let admission_command = roster_production_admission_command(admission.clone(), authority);
        let request_id = admission_command
            .request_id()
            .expect("admission request ID");
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: legacy_identity(),
            request_id,
            logical_time: legacy_time(37),
            intent: SessionMutationIntent::RosterAdmission(Box::new(admission_command)),
        };
        let previous = SessionConsensusEntryDigest::from_bytes([0xD3; 32]);
        let effective = legacy_time(41);
        let baseline = command
            .calculate_applied_digest(5, previous, effective)
            .expect("roster applied digest");
        assert_eq!(
            baseline,
            command
                .calculate_applied_digest(5, previous, effective)
                .expect("deterministic roster applied digest")
        );
        assert_ne!(
            baseline,
            command
                .calculate_applied_digest(6, previous, effective)
                .expect("changed sequence roster digest")
        );
        assert_ne!(
            baseline,
            command
                .calculate_applied_digest(
                    5,
                    SessionConsensusEntryDigest::from_bytes([0xD4; 32]),
                    effective,
                )
                .expect("changed predecessor roster digest")
        );
        assert_ne!(
            baseline,
            command
                .calculate_applied_digest(5, previous, legacy_time(42))
                .expect("changed effective time roster digest")
        );
        assert!(command
            .encode_roster_applied_digest_input(5, previous, effective)
            .expect("roster digest encoding")
            .starts_with(ROSTER_APPLIED_DIGEST_MAGIC));

        let changed_body = roster_digest_admission(0x77);
        let changed_body_command = roster_production_admission_command(
            changed_body.clone(),
            roster_digest_authority(&changed_body, 11, 1, 61),
        );
        let changed_guard_command = roster_production_admission_command(
            admission.clone(),
            roster_digest_authority(&admission, 12, 1, 61),
        );
        let changed_ingress_command = roster_production_admission_command_with_ingress_request_id(
            admission.clone(),
            roster_digest_authority(&admission, 11, 1, 61),
            [0x4a; 16],
        );
        for changed_intent in [
            SessionMutationIntent::RosterAdmission(Box::new(changed_body_command)),
            SessionMutationIntent::RosterAdmission(Box::new(changed_guard_command)),
            SessionMutationIntent::RosterAdmission(Box::new(changed_ingress_command)),
        ] {
            let mut changed = command.clone();
            changed.intent = changed_intent;
            assert_ne!(
                baseline,
                changed
                    .calculate_applied_digest(5, previous, effective)
                    .expect("changed roster inner digest"),
                "every canonical admission body, guard, and ingress mutation binds the chain"
            );
        }

        let mut changed_schema = command.clone();
        changed_schema.schema_version = SESSION_CONSENSUS_SCHEMA_VERSION.saturating_add(1);
        let mut changed_identity = command.clone();
        changed_identity.identity = SessionConsensusIdentity::new(
            SessionConsensusClusterId::new("legacy-cluster").expect("cluster"),
            SessionConsensusConfigurationId::from_bytes([0x42; 32]),
            SessionConsensusConfigurationEpoch::new(3).expect("epoch"),
        );
        let mut changed_request_id = command.clone();
        changed_request_id.request_id = SessionConsensusRequestId::from_bytes([0xD2; 16]);
        let mut changed_logical_time = command.clone();
        changed_logical_time.logical_time = legacy_time(38);
        for changed in [
            changed_schema,
            changed_identity,
            changed_request_id,
            changed_logical_time,
        ] {
            assert_ne!(
                baseline,
                changed
                    .calculate_applied_digest(5, previous, effective)
                    .expect("changed roster outer digest"),
                "outer command metadata is part of the roster chain"
            );
        }

        let mut wrapped = command.clone();
        wrapped.intent = SessionMutationIntent::Authorized {
            origin: SessionConsensusNodeId::new(9).expect("origin"),
            authority_identity: legacy_identity(),
            mutation: match command.intent.clone() {
                SessionMutationIntent::RosterAdmission(command) => {
                    Box::new(SessionMutationIntent::RosterAdmission(command))
                }
                _ => unreachable!("base command is roster admission"),
            },
        };
        let wrapped_digest = wrapped
            .calculate_applied_digest(5, previous, effective)
            .expect("authorized roster digest");
        assert_ne!(
            baseline, wrapped_digest,
            "direct and authorized forms differ"
        );
        let mut changed_origin = wrapped.clone();
        match &mut changed_origin.intent {
            SessionMutationIntent::Authorized { origin, .. } => {
                *origin = SessionConsensusNodeId::new(10).expect("different origin");
            }
            _ => unreachable!("wrapped command remains authorized"),
        }
        assert_ne!(
            wrapped_digest,
            changed_origin
                .calculate_applied_digest(5, previous, effective)
                .expect("changed authorized roster digest"),
            "the authenticated wrapper origin is part of the roster chain"
        );
        let mut changed_wrapper_authority = wrapped.clone();
        match &mut changed_wrapper_authority.intent {
            SessionMutationIntent::Authorized {
                authority_identity, ..
            } => {
                *authority_identity = SessionConsensusIdentity::new(
                    SessionConsensusClusterId::new("legacy-cluster").expect("cluster"),
                    SessionConsensusConfigurationId::from_bytes([0x43; 32]),
                    SessionConsensusConfigurationEpoch::new(4).expect("epoch"),
                );
            }
            _ => unreachable!("wrapped command remains authorized"),
        }
        assert_ne!(
            wrapped_digest,
            changed_wrapper_authority
                .calculate_applied_digest(5, previous, effective)
                .expect("changed authorized authority digest"),
            "the authenticated wrapper authority is part of the roster chain"
        );

        let terminal = roster_production_terminal_command(
            &admission,
            roster_digest_authority(&admission, 11, 1, 61),
        );
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            terminal.registration_parts();
        let changed_proof =
            ConsensusRosterTerminalCommand::new_with_proof_bundle_evidence_and_ingress_request_id(
                ConsensusRosterTerminalCommandInput {
                    binding: terminal.binding(),
                    registration_handle,
                    registration_request_id,
                    registration_terminal_slot,
                    authority: terminal.authority().clone(),
                    record: terminal.record_bytes().to_vec(),
                },
                roster_test_proof_bundle_with_evidence_prefix(&admission, 0x85),
                terminal.terminal_evidence().expect("terminal evidence"),
                terminal.ingress_request_id(),
                terminal.ingress_attestation().expect("terminal ingress"),
            )
            .expect("canonical terminal with changed proof bundle");
        let changed_terminal_guard =
            ConsensusRosterTerminalCommand::new_with_proof_bundle_evidence_and_ingress_request_id(
                ConsensusRosterTerminalCommandInput {
                    binding: terminal.binding(),
                    registration_handle,
                    registration_request_id,
                    registration_terminal_slot,
                    authority: AuthorityBinding::from_consensus_parts(
                        admission.scope().digest(),
                        admission.key().clone(),
                        OwnerId::new("roster-successor-owner").expect("successor owner"),
                        FenceToken::new(8),
                        AuthorityLeaseMetadata::new(
                            12,
                            admission.expected_generation(),
                            legacy_time(2),
                            legacy_time(62),
                        ),
                    )
                    .expect("successor authority"),
                    record: terminal.record_bytes().to_vec(),
                },
                terminal.proof_bundle().expect("terminal proof bundle"),
                terminal.terminal_evidence().expect("terminal evidence"),
                terminal.ingress_request_id(),
                terminal.ingress_attestation().expect("terminal ingress"),
            )
            .expect("canonical terminal with changed current guard");
        let changed_terminal_evidence =
            roster_production_terminal_command_with_terminal_evidence_key_id(
                &admission,
                roster_digest_authority(&admission, 11, 1, 61),
                [0x5f; 32],
            );
        let terminal_command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: legacy_identity(),
            request_id: terminal.request_id().expect("terminal request ID"),
            logical_time: legacy_time(37),
            intent: SessionMutationIntent::RosterTerminal(Box::new(terminal)),
        };
        let mut proof_changed_command = terminal_command.clone();
        proof_changed_command.intent =
            SessionMutationIntent::RosterTerminal(Box::new(changed_proof));
        let mut guard_changed_command = terminal_command.clone();
        guard_changed_command.intent =
            SessionMutationIntent::RosterTerminal(Box::new(changed_terminal_guard));
        let mut evidence_changed_command = terminal_command.clone();
        evidence_changed_command.intent =
            SessionMutationIntent::RosterTerminal(Box::new(changed_terminal_evidence));
        assert_ne!(
            terminal_command
                .calculate_applied_digest(5, previous, effective)
                .expect("terminal roster digest"),
            proof_changed_command
                .calculate_applied_digest(5, previous, effective)
                .expect("changed-proof terminal roster digest"),
            "the exact terminal proof bundle is part of the inner digest"
        );
        assert_ne!(
            terminal_command
                .calculate_applied_digest(5, previous, effective)
                .expect("terminal roster digest"),
            guard_changed_command
                .calculate_applied_digest(5, previous, effective)
                .expect("changed-guard terminal roster digest"),
            "the exact terminal current authority is part of the inner digest"
        );
        assert_ne!(
            terminal_command
                .calculate_applied_digest(5, previous, effective)
                .expect("terminal roster digest"),
            evidence_changed_command
                .calculate_applied_digest(5, previous, effective)
                .expect("changed-evidence terminal roster digest"),
            "the exact terminal compact evidence is part of the inner digest"
        );
    }

    #[test]
    fn roster_terminal_digest_replaces_current_guard_but_not_immutable_body() {
        let admission = roster_digest_admission(0x76);
        let request_id = RequestId::bind(9, &admission).expect("request ID");
        let changed_body = TerminalRecord::new(
            &admission,
            request_id,
            Phase::Aborted,
            vec![[0x79; 32]; FRESH_ROSTER_MEMBERS],
        )
        .expect("aborted record")
        .to_canonical_bytes(&admission)
        .expect("aborted bytes");

        let original = roster_production_terminal_command(
            &admission,
            roster_digest_authority(&admission, 11, 1, 61),
        );
        let binding = original.binding();
        let (handle, request_id, terminal_slot) = original.registration_parts();
        let established = original.record_bytes().to_vec();
        let encoded = postcard::to_allocvec(&original).expect("production terminal command wire");
        let decoded = postcard::from_bytes::<ConsensusRosterTerminalCommand>(&encoded)
            .expect("production terminal command round trip");
        assert_eq!(
            encoded,
            postcard::to_allocvec(&decoded).expect("re-encoded terminal wire"),
            "the non-wire digest cache must not alter terminal command bytes"
        );
        assert_eq!(
            original.immutable_payload_digest(),
            decoded.immutable_payload_digest()
        );
        assert_eq!(
            original.exact_attempt_digest().expect("attempt digest"),
            decoded.exact_attempt_digest().expect("attempt digest"),
            "deserialization rebuilds, rather than trusts, the exact digest cache"
        );
        assert_eq!(
            original
                .proof_bundle()
                .expect("original proof bundle")
                .canonical_bytes()
                .expect("original proof bytes"),
            decoded
                .proof_bundle()
                .expect("decoded proof bundle")
                .canonical_bytes()
                .expect("decoded proof bytes")
        );
        let malformed = ConsensusRosterTerminalWire {
            binding: original.binding(),
            registration_handle: original.registration_handle,
            registration_request_id: original.registration_request_id,
            registration_terminal_slot: original.registration_terminal_slot,
            authority: original.authority().into(),
            record: BoundedRosterCapsule::new(vec![0]).expect("bounded malformed terminal"),
            proof_bundle: original.proof_bundle.clone(),
            terminal_evidence: original.terminal_evidence.clone(),
            ingress_request_id: original.ingress_request_id(),
            ingress_attestation: original.ingress_attestation.clone(),
        };
        let malformed = postcard::to_allocvec(&malformed).expect("malformed terminal wire");
        assert!(
            postcard::from_bytes::<ConsensusRosterTerminalCommand>(&malformed).is_err(),
            "a malformed canonical terminal never obtains a digest cache"
        );
        let successor = AuthorityBinding::from_consensus_parts(
            admission.scope().digest(),
            admission.key().clone(),
            OwnerId::new("roster-successor-owner").expect("successor owner"),
            FenceToken::new(8),
            AuthorityLeaseMetadata::new(
                12,
                admission.expected_generation(),
                legacy_time(2),
                legacy_time(62),
            ),
        )
        .expect("successor authority");
        let takeover = roster_terminal_command(
            &admission,
            ConsensusRosterTerminalCommandInput {
                binding,
                registration_handle: handle,
                registration_request_id: request_id,
                registration_terminal_slot: terminal_slot,
                authority: successor,
                record: established,
            },
        );
        let conflicting = roster_terminal_command(
            &admission,
            ConsensusRosterTerminalCommandInput {
                binding,
                registration_handle: handle,
                registration_request_id: request_id,
                registration_terminal_slot: terminal_slot,
                authority: roster_digest_authority(&admission, 13, 3, 63),
                record: changed_body,
            },
        );

        assert_eq!(
            original.request_id().expect("request ID"),
            takeover.request_id().expect("request ID")
        );
        assert_eq!(
            original.immutable_payload_digest(),
            takeover.immutable_payload_digest()
        );
        assert_ne!(
            original.exact_attempt_digest().expect("original attempt"),
            takeover.exact_attempt_digest().expect("takeover attempt")
        );
        assert!(!original
            .outcome_binding()
            .expect("old-guard response binding")
            .matches_terminal(&takeover)
            .expect("compare exact attempts"));
        assert_ne!(
            original.immutable_payload_digest(),
            conflicting.immutable_payload_digest()
        );
    }

    #[test]
    fn compacted_terminal_outcome_requires_the_derived_registration_handle() {
        let admission = roster_digest_admission(0x76);
        let request_id = RequestId::bind(9, &admission).expect("request ID");
        let binding = admission.binding_key(9).expect("binding");
        let derived_handle = roster_registration_handle(binding);
        let registration =
            BackendRegistration::from_consensus_parts(derived_handle, request_id, &admission)
                .expect("registration");
        let (_, request_id, terminal_slot) = registration.consensus_parts();
        let terminal = TerminalRecord::new(
            &admission,
            request_id,
            Phase::Established,
            vec![[0x79; 32]; FRESH_ROSTER_MEMBERS],
        )
        .expect("terminal record");
        let tombstone =
            TerminalConflictTombstone::new(&admission, &terminal).expect("terminal tombstone");
        let successor = AuthorityBinding::from_consensus_parts(
            admission.scope().digest(),
            admission.key().clone(),
            OwnerId::new("roster-successor-owner").expect("successor owner"),
            FenceToken::new(8),
            AuthorityLeaseMetadata::new(
                12,
                admission.expected_generation(),
                legacy_time(2),
                legacy_time(62),
            ),
        )
        .expect("successor authority");
        let terminal_bytes = terminal
            .to_canonical_bytes(&admission)
            .expect("terminal bytes");
        let exact = roster_terminal_command(
            &admission,
            ConsensusRosterTerminalCommandInput {
                binding,
                registration_handle: derived_handle,
                registration_request_id: request_id,
                registration_terminal_slot: *terminal_slot.as_bytes(),
                authority: successor.clone(),
                record: terminal_bytes.clone(),
            },
        );
        ConsensusRosterTerminalOutcome::compacted(&exact, 9, tombstone.clone())
            .expect("exact compacted outcome");

        let forged = roster_terminal_command(
            &admission,
            ConsensusRosterTerminalCommandInput {
                binding,
                registration_handle: [0x78; 32],
                registration_request_id: request_id,
                registration_terminal_slot: *terminal_slot.as_bytes(),
                authority: successor,
                record: terminal_bytes,
            },
        );
        assert!(ConsensusRosterTerminalOutcome::compacted(&forged, 9, tombstone).is_err());
    }

    #[test]
    fn roster_variants_append_after_existing_consensus_wire_tags() {
        let admission = roster_digest_admission(0x76);
        let admission_command = ConsensusRosterAdmissionCommand::new(
            admission.clone(),
            roster_digest_authority(&admission, 11, 1, 61),
        )
        .expect("admission command");
        let request_id = RequestId::bind(9, &admission).expect("request ID");
        let binding = admission.binding_key(9).expect("binding");
        let registration =
            BackendRegistration::from_consensus_parts([0x78; 32], request_id, &admission)
                .expect("registration");
        let (handle, request_id, terminal_slot) = registration.consensus_parts();
        let record = TerminalRecord::new(
            &admission,
            request_id,
            Phase::Established,
            vec![[0x79; 32]; FRESH_ROSTER_MEMBERS],
        )
        .expect("terminal record")
        .to_canonical_bytes(&admission)
        .expect("terminal bytes");
        let terminal_command = roster_terminal_command(
            &admission,
            ConsensusRosterTerminalCommandInput {
                binding,
                registration_handle: handle,
                registration_request_id: request_id,
                registration_terminal_slot: *terminal_slot.as_bytes(),
                authority: roster_digest_authority(&admission, 11, 1, 61),
                record,
            },
        );
        let admission_outcome_binding = admission_command
            .outcome_binding()
            .expect("admission outcome binding");
        let terminal_outcome_binding = terminal_command
            .outcome_binding()
            .expect("terminal outcome binding");

        assert_eq!(
            postcard::to_allocvec(&SessionMutationIntent::PreflightFencedTransitionCapability)
                .expect("existing intent")[0],
            22
        );
        assert_eq!(
            postcard::to_allocvec(&SessionMutationIntent::ActivateFencedTransitionCapability {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                scope_identity: legacy_identity(),
                voter_set_digest: [0x82; 32],
            })
            .expect("existing intent")[0],
            23
        );
        assert_eq!(
            postcard::to_allocvec(&SessionMutationIntent::RosterAdmission(Box::new(
                admission_command
            )))
            .expect("admission intent")[0],
            24
        );
        assert_eq!(
            postcard::to_allocvec(&SessionMutationIntent::RosterTerminal(Box::new(
                terminal_command
            )))
            .expect("terminal intent")[0],
            25
        );
        assert_eq!(
            postcard::to_allocvec(&SessionMutationIntent::PreflightProtectedRosterProfile)
                .expect("protected roster profile preflight intent")[0],
            26
        );
        assert_eq!(
            postcard::to_allocvec(&SessionMutationOutcome::FencedTransition(
                FencedTransitionOutcome::new(
                    legacy_lease(legacy_key(), OwnerId::new("legacy-owner").expect("owner")),
                    Generation::new(3),
                    FencedTransitionMutationResult::Created,
                    legacy_time(1),
                )
                .expect("existing outcome")
            ))
            .expect("existing outcome")[0],
            4
        );
        assert_eq!(
            postcard::to_allocvec(&SessionMutationOutcome::RosterAdmission(
                ConsensusRosterAdmissionOutcome::Rejected {
                    outcome_binding: admission_outcome_binding,
                    rejection: ConsensusRosterRejection::Authority,
                }
            ))
            .expect("admission outcome")[0],
            6
        );
        assert_eq!(
            postcard::to_allocvec(&SessionMutationOutcome::RosterTerminal(
                ConsensusRosterTerminalOutcome::Rejected {
                    outcome_binding: terminal_outcome_binding,
                    rejection: ConsensusRosterRejection::Authority,
                }
            ))
            .expect("terminal outcome")[0],
            7
        );
    }

    #[test]
    fn consensus_command_and_response_debug_are_non_identifying() {
        let key = SessionKey {
            tenant: TenantId::from_static("debug-secret-tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"debug-secret-key")).expect("stable ID"),
        };
        let owner = OwnerId::new("debug-secret-owner").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0xA7; 16]),
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(0),
                Duration::from_secs(60),
            )
            .expect("lease action"),
            FencedTransitionMutation::create(StoredSessionRecord {
                key,
                generation: Generation::new(1),
                owner,
                fence: FenceToken::new(1),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::from_static("debug-secret-type"),
                expires_at: None,
                payload: EncryptedSessionPayload::new(b"debug-secret-payload"),
            }),
        )
        .expect("transition request");
        let logical_time = opc_types::Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_234_567),
        );
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: SessionConsensusIdentity::new(
                SessionConsensusClusterId::new("debug-secret-cluster").expect("cluster"),
                SessionConsensusConfigurationId::from_bytes([0xA8; 32]),
                SessionConsensusConfigurationEpoch::new(7).expect("epoch"),
            ),
            request_id: SessionConsensusRequestId::from_bytes([0xA7; 16]),
            logical_time,
            intent: SessionMutationIntent::FencedTransition(Box::new(request)),
        };
        let response = SessionConsensusResponse {
            result: Err(StoreError::BackendUnavailable(
                "debug-secret-diagnostic".into(),
            )),
            sequence: 9,
            digest: Some(SessionConsensusEntryDigest::from_bytes([0xA9; 32])),
            logical_time: Some(logical_time),
            raft_log_index: 10,
        };

        assert_eq!(
            format!("{command:?}"),
            "SessionConsensusCommand(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", command.intent),
            "SessionMutationIntent(<redacted>)"
        );
        assert_eq!(
            format!("{response:?}"),
            "SessionConsensusResponse(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", SessionMutationOutcome::Unit),
            "SessionMutationOutcome(<redacted>)"
        );
        let rpc = SessionConsensusRpc::new(
            command.identity,
            SessionConsensusNodeId::new(3).expect("sender"),
            b"debug-secret-rpc".to_vec(),
        );
        assert_eq!(format!("{rpc:?}"), "SessionConsensusRpc(<redacted>)");
        for secret in [
            "debug-secret",
            "1234567",
            "A7",
            "A8",
            "A9",
            "ConsensusIdentity",
        ] {
            assert!(!format!("{command:?}{response:?}{rpc:?}").contains(secret));
        }
    }
}
