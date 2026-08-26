//! Generic, bounded protected atomic-mutation roster contract.
//!
//! Provider I/O is deliberately outside consensus. This module owns only the
//! immutable proposal, its authenticated admission, and terminal persistence.

use async_trait::async_trait;
use opc_session_store::{
    consensus::SessionConsensusIdentity,
    fenced_mutation_roster::{
        RosterAttestationCertificateRoleV1, RosterAttestationLeafCertificatePartsV1,
        RosterProviderOperationV1, RosterProviderOutcomeV1,
    },
    FenceToken, Generation, OwnerId, SessionKey, StateType,
};
use opc_types::Timestamp;
use serde::{
    de::{SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, marker::PhantomData};

/// Schema version of the sole protected-roster wire profile.
pub const SCHEMA_V1: u16 = 1;
/// Consumer revision negotiated by the sole protected-roster profile.
pub const CONSUMER_REVISION: u16 = 5;
/// Revision-five consumer ALPN, frozen into the profile descriptor.
pub const CONSUMER_ALPN: &[u8] = b"opc-session-consumer/3";
/// Maximum number of ordered member operations in one roster.
pub const MAX_MEMBERS: usize = 8;
/// Member count targeted for a newly admitted operational roster.
pub const FRESH_ROSTER_MEMBERS: usize = 6;
/// Maximum byte length of a protected plan.
pub const MAX_PLAN_BYTES: usize = 1 << 20;
/// Maximum byte length of a protected terminal checkpoint.
pub const MAX_CHECKPOINT_BYTES: usize = 1 << 20;
/// Maximum byte length of a protected terminal result.
pub const MAX_RESULT_BYTES: usize = 16 << 10;
/// Byte width of a [`RosterId`].
pub const ROSTER_ID_BYTES: usize = 16;
/// Byte width of a [`MemberOperationId`].
pub const MEMBER_OPERATION_ID_BYTES: usize = 16;
/// Maximum byte length of an opaque member descriptor.
pub const MAX_DESCRIPTOR_BYTES: usize = 16 << 10;
/// Maximum byte length of provider status or conclusive evidence.
pub const MAX_STATUS_BYTES: usize = 4 << 10;
/// Maximum number of live admitted rosters.
pub const MAX_LIVE_ROSTERS: usize = 1_024;
/// Maximum combined number of live and retained terminal rosters.
pub const MAX_RESERVED_AND_RETAINED: usize = 131_072;
/// Operational live-and-retained roster target committed by the profile.
pub(crate) const OPERATIONAL_TARGET: usize = 100_000;
/// Largest history epoch accepted by durable SQLite-backed implementations.
pub const MAX_HISTORY_EPOCH: u64 = i64::MAX as u64;

const PROFILE_DOMAIN: &[u8] = b"opc/session-store/protected-roster/profile/v1\0";
const ADMISSION_DOMAIN: &[u8] = b"opc/session-store/protected-roster/admission/v1\0";
const DESCRIPTOR_DOMAIN: &[u8] = b"opc/session-store/protected-roster/descriptor/v1\0";
const TERMINAL_DOMAIN: &[u8] = b"opc/session-store/protected-roster/terminal/v1\0";
const TERMINAL_SLOT_DOMAIN: &[u8] = b"opc/session-store/protected-roster/terminal-slot/v1\0";
const SESSION_KEY_BINDING_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/session-key-binding/v1\0";
const TENANT_SCOPE_PARTITION_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/tenant-scope-partition/v1\0";
const PROVIDER_FENCE_BINDING_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/provider-fence-binding/v1\0";
const PUBLICATION_ID_DOMAIN: &[u8] = b"opc/session-store/protected-roster/publication-id/v1\0";
const PUBLICATION_PAYLOAD_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/publication-payload/v1\0";
const PUBLICATION_EVIDENCE_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/publication-evidence/v1\0";
const TOMBSTONE_FRAME_DOMAIN: &[u8] = b"opc/session-store/protected-roster/tombstone-frame/v3\0";
/// Binds the compact terminal's exact Raft position to the immutable roster
/// admission and terminal body after their full retained copies are reclaimed.
const TOMBSTONE_TERMINAL_INDEX_BINDING_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/tombstone-terminal-index-binding/v1\0";
/// Commits the immutable admission owner without retaining its plaintext
/// identity in the compact tombstone.
const TOMBSTONE_ADMISSION_OWNER_COMMITMENT_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/tombstone-admission-owner-commitment/v1\0";
const HISTORY_FLOOR_FRAME_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/history-floor-frame/v1\0";
const ADMISSION_FRAME_DOMAIN: &[u8] = b"opc/session-store/protected-roster/admission-frame/v1\0";
const TERMINAL_FRAME_DOMAIN: &[u8] = b"opc/session-store/protected-roster/terminal-frame/v1\0";
/// Domain for the durable atomic terminal record/receipt composite frame.
pub(crate) const COMMITTED_TERMINAL_FRAME_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/committed-terminal-frame/v1\0";
const ADMISSION_FRAME_MAGIC: [u8; 8] = *b"OPCRAD2\0";
const TERMINAL_FRAME_MAGIC: [u8; 8] = *b"OPCRTM2\0";
/// Magic for the durable atomic terminal record/receipt composite frame.
pub(crate) const COMMITTED_TERMINAL_FRAME_MAGIC: [u8; 8] = *b"OPCRCT1\0";
const TOMBSTONE_FRAME_MAGIC: [u8; 8] = *b"OPCRTB3\0";
const HISTORY_FLOOR_FRAME_MAGIC: [u8; 8] = *b"OPCRHF1\0";
/// Domain separating executor-owned proof commitments from roster commitments.
pub(crate) const PROOF_DOMAIN: &[u8] = b"opc/session-store/protected-roster/executor-proof/v1\0";
/// Domain separating opaque executor evidence commitments.
pub(crate) const EXECUTOR_EVIDENCE_DOMAIN: &[u8] =
    b"opc/session-store/protected-roster/executor-evidence/v1\0";
/// Domain for the guard that authorized the irreversible terminal transaction.
pub(crate) const TERMINAL_COMMITTING_GUARD_DOMAIN: &[u8] =
    b"openpacketcore/fenced-mutation-roster/terminal-committing-guard/v1";
/// Domain for an Established Put's immutable authoritative session header.
pub(crate) const TERMINAL_RECORD_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/fenced-mutation-roster/terminal-session-record/v1";
/// Domain for the complete atomic terminal receipt.
pub(crate) const TERMINAL_RECEIPT_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/fenced-mutation-roster/terminal-receipt/v1";
/// Domain for the exact authenticated tenant/scope provider scheduling class.
pub(crate) const PROVIDER_SCHEDULING_DOMAIN: &[u8] =
    b"openpacketcore/fenced-mutation-roster/provider-scheduling/v1";
pub(crate) const PROOF_BINDING_DOMAIN: &[u8] = b"binding\0";
pub(crate) const PROOF_DESCRIPTOR_DOMAIN: &[u8] = b"descriptor\0";
pub(crate) const PROOF_OWNER_DOMAIN: &[u8] = b"owner\0";
pub(crate) const PROOF_CREDENTIAL_DOMAIN: &[u8] = b"credential\0";
const ROSTER_ATTESTATION_ROOT_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-attestation-root/v1\0";
const ROSTER_ATTESTATION_CERTIFICATE_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-attestation-certificate/v1\0";
const ROSTER_ATTESTATION_PROOF_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-attestation-proof/v1\0";
const ROSTER_ATTESTATION_PROVIDER_RECEIPT_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-attestation-provider-receipt/v1\0";
const ROSTER_ATTESTATION_STABLE_PROOF_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-attestation-stable-proof/v1\0";
const ROSTER_ATTESTATION_EVIDENCE_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-attestation-evidence/v1\0";
const ROSTER_ATTESTATION_BUNDLE_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-attestation-bundle/v1\0";
const ROSTER_INGRESS_ATTESTATION_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-ingress-attestation/v1\0";
const ROSTER_INGRESS_CAPSULE_DOMAIN: &[u8] = b"openpacketcore/session-consumer/roster-capsule/v1\0";
const ROSTER_COMPACT_ADMISSION_PROVENANCE_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-compact-admission-provenance/v2\0";
const ROSTER_COMPACT_ADMISSION_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-compact-admission-commitment/v2\0";
const ROSTER_COMPACT_ADMISSION_FIELD_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-compact-admission-field/v2\0";
const ROSTER_COMPACT_ADMISSION_SLOT_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/roster-admission-slot/v2\0";
const ROSTER_COMPACT_TERMINAL_EVIDENCE_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-compact-terminal-evidence/v2\0";
const ROSTER_COMPACT_TERMINAL_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-compact-terminal-commitment/v2\0";
const ROSTER_ATTESTATION_PROVIDER_RECEIPT_MAGIC: [u8; 8] = *b"OPCPRC1\0";
const ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES: usize = 33;
const ROSTER_ATTESTATION_P256_SIGNATURE_BYTES: usize = 64;
const MAX_EXECUTOR_PROOF_EVIDENCE_BYTES: usize = MAX_STATUS_BYTES;
const MAX_EXECUTOR_PROOF_BUNDLE_BYTES: usize = 40 * 1024;
const MAX_COMPACT_TERMINAL_EVIDENCE_BYTES: usize = 8 * 1024;
pub(crate) const PROVIDER_OPERATION_EXECUTE_TAG: u8 = 1;
pub(crate) const PROVIDER_OPERATION_STATUS_TAG: u8 = 2;
pub(crate) const PROVIDER_OPERATION_ADOPT_TAG: u8 = 3;
pub(crate) const PROVIDER_OPERATION_COMPENSATE_TAG: u8 = 4;
pub(crate) const PROVIDER_OPERATION_PREPARE_TAG: u8 = 5;
pub(crate) const PROVIDER_OPERATION_RECONCILE_TAG: u8 = 6;
const PUBLICATION_OPERATION_STATUS_TAG: u8 = 1;
const PUBLICATION_OPERATION_BEGIN_INTENT_TAG: u8 = 2;
const PUBLICATION_OPERATION_ADOPT_TAG: u8 = 3;
const FRAME_HEADER_BYTES: usize = 14;
const FRAME_DIGEST_BYTES: usize = 32;
/// Fixed descriptor-bound maximum for an authenticated admission frame.
pub(crate) const MAX_ADMISSION_CODEC_BYTES: usize = 2_245_658;
/// Fixed descriptor-bound maximum for a terminal record frame.
pub(crate) const MAX_TERMINAL_CODEC_BYTES: usize = 1_065_423;
/// Fixed descriptor-bound maximum for a committed terminal composite frame.
pub(crate) const MAX_COMMITTED_TERMINAL_CODEC_BYTES: usize =
    MAX_TERMINAL_CODEC_BYTES + MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES;
/// Fixed descriptor-bound maximum for a compact conflict-tombstone frame.
pub(crate) const MAX_TOMBSTONE_CODEC_BYTES: usize = 256;
/// Conservative receipt/header overhead beyond its separately charged record.
pub(crate) const MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES: usize = 4_096;

const PHASE_ESTABLISHED: u8 = 1;
const PHASE_ABORTED: u8 = 2;
const ESTABLISHED_MUTATION_PUT_CHECKPOINT: u8 = 1;
const ESTABLISHED_MUTATION_DELETE: u8 = 2;
const ESTABLISHED_MUTATION_NO_OP: u8 = 3;
const OUTCOME_APPLIED_EXECUTED: u8 = 1;
const OUTCOME_APPLIED_ADOPTED: u8 = 2;
const OUTCOME_NOT_APPLIED_RECONCILED: u8 = 3;
const OUTCOME_COMPENSATED_RECONCILED: u8 = 4;
pub(crate) const PROVIDER_NOT_TRANSMITTED: u8 = 1;
pub(crate) const PROVIDER_OUTCOME_UNKNOWN: u8 = 2;
pub(crate) const PROVIDER_NOT_FOUND: u8 = 3;
pub(crate) const PROVIDER_PENDING: u8 = 4;
pub(crate) const PROVIDER_CONCLUSIVE: u8 = 5;
pub(crate) const PROVIDER_PREPARED_NOT_RUN: u8 = 6;
pub(crate) const PROVIDER_READY_TO_PREPARE: u8 = 7;
const PUBLICATION_ABSENT: u8 = 1;
const PUBLICATION_NOT_TRANSMITTED: u8 = 2;
const PUBLICATION_OUTCOME_UNKNOWN: u8 = 3;
const PUBLICATION_PENDING: u8 = 4;
const PUBLICATION_PUBLISHED: u8 = 5;
const PUBLICATION_CONFLICT: u8 = 6;

/// Immutable negotiated limits for the sole protected-roster profile.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Profile {
    schema: u16,
    consumer_revision: u16,
    digest: [u8; 32],
}
impl Profile {
    /// Return the one supported protected-roster profile.
    pub fn v1() -> Self {
        Self {
            schema: SCHEMA_V1,
            consumer_revision: CONSUMER_REVISION,
            digest: profile_digest(),
        }
    }
    /// Return this profile's schema version.
    pub const fn schema(self) -> u16 {
        self.schema
    }
    /// Return this profile's consumer revision.
    pub const fn consumer_revision(self) -> u16 {
        self.consumer_revision
    }
    /// Return the descriptor-bound digest that identifies this profile.
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
    /// Verify that this value is exactly the supported profile.
    pub fn validate(self) -> Result<(), Error> {
        if self == Self::v1() {
            Ok(())
        } else {
            Err(Error::CapabilityMismatch)
        }
    }
}
impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Profile(<redacted>)")
    }
}
#[derive(Deserialize)]
struct ProfileWire {
    schema: u16,
    consumer_revision: u16,
    digest: [u8; 32],
}
impl<'de> Deserialize<'de> for Profile {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = ProfileWire::deserialize(d)?;
        let p = Self {
            schema: w.schema,
            consumer_revision: w.consumer_revision,
            digest: w.digest,
        };
        p.validate().map_err(serde::de::Error::custom)?;
        Ok(p)
    }
}

const PROFILE_DESCRIPTOR: &[u8] = concat!(
    "schema=1\n",
    "consumer-revision=5\n",
    "alpn=opc-session-consumer/3\n",
    "codec=postcard-canonical,frame-digest=sha256\n",
    "domains=profile,admission,descriptor,terminal,terminal-slot,session-key-binding,tenant-scope-partition,provider-fence-binding,publication-id,publication-payload,publication-evidence,admission-frame,terminal-frame,committed-terminal-frame,tombstone-frame,tombstone-terminal-index-binding,tombstone-admission-owner-commitment,history-floor-frame,executor-proof,executor-evidence,terminal-committing-guard,terminal-session-record,terminal-receipt,provider-scheduling,binding,descriptor,owner,credential,roster-attestation-root,roster-attestation-certificate,roster-attestation-proof,roster-attestation-provider-receipt,roster-attestation-stable-proof,roster-attestation-evidence,roster-attestation-bundle,roster-ingress-attestation,roster-ingress-capsule,roster-compact-admission-provenance,roster-compact-admission-commitment,roster-compact-admission-field,roster-compact-admission-slot,roster-compact-terminal-evidence,roster-compact-terminal-commitment\n",
    "magics=OPCRAD2\\0,OPCRTM2\\0,OPCRCT1\\0,OPCRTB3\\0,OPCRHF1\\0,OPCPRC1\\0\n",
    "field-order=profile,roster,members,established-mutation,plan,checkpoint,result;key,scope,owner,fence,generation;binding:epoch,scope,tenant-scope-partition,session-key-commitment,roster-id;tombstone:scope,admission-commitment,terminal-commitment,admission-owner-commitment,admission-fence,generation,phase,terminal-raft-log-index,terminal-index-binding;history-floor:scope,tenant-scope-partition,retired-through\n",
    "executor-field-order=proof-binding:roster-attestation-proof,profile,configuration-identity,certificate-subject,certificate-role,binding,registration-handle,registration-request-id,terminal-slot,roster-id,admission-commitment,terminal-phase,terminal-body-commitment,ordinal,stable-member-operation-id,descriptor-length,descriptor,descriptor-commitment,expected-version,expected-generation,immutable-authority-scope,current-ingress-scope,key,owner-commitment,fence,credential-commitment,generation,acquired-at-nanos,expires-at-nanos,proof-epoch,operation,outcome,evidence-length,evidence,evidence-commitment;provider-receipt=roster-attestation-provider-receipt,profile,configuration-identity,provider-certificate-subject,provider-role,binding,registration-handle,registration-request-id,terminal-slot,roster-id,admission-commitment,ordinal,stable-member-operation-id,descriptor-length,descriptor,descriptor-commitment,expected-version,expected-generation,immutable-authority-scope,current-ingress-scope,key,owner-commitment,fence,credential-commitment,generation,acquired-at-nanos,expires-at-nanos,proof-epoch,operation,outcome,evidence-length,evidence,evidence-commitment;proof-commitment:roster-attestation-stable-proof,binding,registration-request-id,terminal-slot,roster-id,admission-commitment,phase,ordinal,stable-member-operation-id,descriptor-length,descriptor,descriptor-commitment,expected-version,expected-generation,outcome,evidence-commitment;certificate=roster-attestation-certificate,version,root-id,role,configuration-identity,scope,subject,leaf-epoch,key-id[32],not-before,not-after,compressed-p256-key;attestation=p256-sha256,compressed-sec1:33,low-s-p1363:64,roles:executor|provider|transport-ingress;ingress=roster-ingress-attestation,profile-alpn,peer,scope,request,operation,capsule,authenticated-at,peer-cert-expires,material-generation,handshake-epoch;provider-operations=local-prepare-execute-status-adopt-compensate-reconcile\n",
    "committed-terminal-frame-field-order=record,commit-metadata(sequence,raft-log-index,committed-at),committing-registration-handle,committing-registration-request-id,committing-registration-terminal-slot-id,committing-authority-scope,committing-authority-ingress-scope,committing-authority-key,committing-authority-owner,committing-authority-fence,committing-authority-credential,committing-authority-generation,committing-authority-acquired-at,committing-authority-expires-at,committing-guard-commitment,materialization,receipt-commitment;materialization-postcard-tags=updated:0,deleted:1,no-op:2,aborted:3\n",
    "terminal-guard-field-order=profile,committing-registration-handle,committing-registration-request-id,committing-registration-terminal-slot-id,admission-commitment,immutable-authority-scope,current-ingress-scope,key,owner,fence,credential,generation,acquired-at,expires-at\n",
    "compact-admission-provenance-field-order=input:profile,configuration-identity,certificate-subject,certificate-role,scope,tenant-scope-partition,session-key-commitment,admission-slot,roster-id,admission-commitment,members(count;ordinal,stable-member-operation-id,descriptor-length,descriptor-commitment,expected-version),established-mutation-tag,optional-established-state-type(length,commitment),protected-plan(length,commitment),protected-checkpoint(length,commitment),protected-result(length,commitment),logical-owner-commitment,admission-fence,expected-generation,authority-scope,authority-key-commitment,authority-owner-commitment,authority-fence,authority-credential-id,authority-generation,authority-acquired-at,authority-expires-at,ingress;envelope=certificate,input,signature\n",
    "compact-terminal-evidence-field-order=binding:profile,configuration-identity,certificate-subject,certificate-role,admission-provenance-commitment,binding,registration-handle,registration-request-id,terminal-slot,roster-id,admission-commitment,terminal-phase,terminal-body-commitment,checkpoint-length,checkpoint-commitment,result-length,result-commitment,immutable-authority-scope,current-ingress-scope,key-commitment,owner-commitment,fence,credential,generation,acquired-at,expires-at;member:ordinal,stable-member-operation-id,descriptor-length,descriptor-commitment,expected-version,expected-generation,proof-epoch,operation,outcome,evidence-length,evidence-commitment,stable-proof-commitment;proof=member,provider-certificate,provider-signature,executor-signature;bundle=executor-certificate,binding,proofs\n",
    "terminal-receipt-field-order=profile,registration-request-id,terminal-slot-id,admission-commitment,terminal-body-commitment,phase,committing-fence,committing-guard-commitment,commit-metadata,materialization;materialization=updated-from-to-record-commitment|deleted-generation|no-op-generation|aborted\n",
    "executor-operation-tags=execute:1,status:2,adopt:3,compensate:4,prepare:5,reconcile:6\n",
    "publication-operation-tags=status:1,begin-inert-intent:2,adopt:3;publication-outcome-tags=absent:1,not-transmitted:2,outcome-unknown:3,pending:4,published:5,conflict:6\n",
    "phase-tags=established:1,aborted:2\n",
    "established-mutation-tags=put-checkpoint:1,delete:2,no-op:3\n",
    "established-put=authoritative-session,exact-admitted-envelope-v1,original-owner-fence,successor-generation,no-expiry\n",
    "admission-business-reservation=exact-present-generation,key-exclusive-through-terminalization,complete-protected-checkpoint-validation,generation-overflow-rejected-before-effects\n",
    "aggregate-storage=deterministic-roster-ledger-schema-charge,dedicated-roster-snapshot-materialized-plus-future-reserved-budget,admission-reserves-terminal-peak,terminal-converts-without-capacity-check,reclaim-retained-to-tombstone,retirement-releases;charge-v1=page:4096,live-row:512,retained-row:384,tombstone-row:128,live-index:192,retained-index:160,tombstone-index:96,receipt-overhead-max:4096,business-header-max:4096\n",
    "roster-local-charge=deterministic-roster-ledger-logical-schema-charge-only,not-raw-sqlite-or-global-store-cap;PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES=274877906944,CHARGE_WITNESS_VERSION=1\n",
    "provider-scheduling=fail-fast,global-max:1024,exact-tenant-scope-cap:ceil(global/2),fixed-shards:16,no-wait-queue,no-per-subscriber-resource\n",
    "provider-tags=not-transmitted:1,outcome-unknown:2,not-found:3,pending:4,conclusive:5,prepared-not-run:6,ready-to-prepare:7\n",
    "outcome-tags=applied-executed:1,applied-adopted:2,not-applied-reconciled:3,compensated-reconciled:4\n",
    "conclusive-matrix=prepare:none;execute:applied-executed;status:applied-executed|applied-adopted|not-applied-reconciled|compensated-reconciled;adopt:applied-adopted|not-applied-reconciled|compensated-reconciled;compensate:compensated-reconciled;reconcile:not-applied-reconciled|compensated-reconciled\n",
    "limits=max-members:8,accepted-members:1..8,fresh-target-members:6,plan:1048576,checkpoint:1048576,result:16384,roster-id:16,member-operation-id:16,descriptor:16384,status:4096,attestation-evidence:4096,attestation-bundle:40960,compact-terminal-evidence:8192,ingress-attestation:1024,admission-codec:2245658,terminal-codec:1065423,committed-terminal-codec:1069519,tombstone-codec:256,history-floor-codec:128,history-epoch-max:9223372036854775807,live:1024,live-plus-retained:131072,epoch-bindings:131072,operational-target:100000,reclaim:1024,retention-seconds:86400,quorum-mutations:fresh-success=2(admission,terminalization);remote-reads=admission-status,recover,terminal-status,current-publication-authority;local-authority-checks=provider-pre-post,publication-pre-post\n",
    "maintenance=bounded-deterministic-reclaim-and-retirement,payload-compaction,irreversible-floor-retirement;never-on-fresh-success;local-provider-journal-only\n",
    "history=stable-slot-binds-epoch-scope-session-key-roster-id,new-v2-admission-atomically-selects-binds-current-epoch-greater-than-durable-exact-scope-floor-before-reserve,admit-reserves-one-terminal-slot,terminal-retention-starts-at-terminalization,reclaim-oldest-min-1024-eligible-to-v3-conflict-tombstone,compact-tombstone-retains-profile-bound-owner-commitment-and-committed-terminal-raft-log-index-bound-to-request-binding-admission-and-terminal-body,never-reclaim-live,durable-canonical-scope-bound-irreversible-floor,never-reopen-before-scope-bound-irreversible-epoch-retirement\n",
    "retry=any-provider-operation-only-after-its-direct-identical-retained-call-not-transmitted,outcome-unknown-status-adopt-only,not-found-non-exclusionary\n",
    "provider-fence=atomically-track-monotonic-current-execution-fence-per-exact-member-binding(roster-id,admission-commitment,scope,tenant,ordinal,stable-member-operation-id,descriptor,expected-version),reject-delayed-lower-fence-execute-after-higher-fence-status-or-adopt-conclusive-not-applied-or-compensated\n",
    "terminal=phase-inferred-from-complete-local-provider-proofs,prepared-body-local,first-conclusive-member-outcome-and-evidence-commitment-immutable-across-successors,established-alone-mints-publication-authority,aborted-nonpublishing,checkpoint-and-result-retained-exactly-through-terminal-retention,then-full-copies-atomically-deleted-and-payload-compacted-to-nonpublishing-conflict-status\n",
    "publication=provider-local-durable-inert-intent-then-adopt,no-consensus-mutation,stable-id-excludes-replaceable-current-fence,current-authority-read-before-and-after-effect,status-first,monotonic-state:absent-to-reserved-to-attempted-to-published,conflict-sticky,created-state-never-reverts-to-absent,logical-state-may-compact-but-not-gc,absent-non-exclusionary-never-effect-authority,begin-never-crosses-effect,adopt-durably-marks-attempted-before-effect,attempted-resend-only-after-provider-retained-exact-not-transmitted,each-call-atomically-raises-durable-fence-floor-and-rejects-lower-or-expired-before-io,outcome-unknown-status-adopt-only,published-tombstone-outlives-terminal-retention,ack-only-after-exact-established-and-postcheck\n"
).as_bytes();

// Keep the numeric profile literal and the internal maintenance target aligned.
const _: () = assert!(OPERATIONAL_TARGET == 100_000);

/// Compute the domain-separated digest of every frozen profile item.
pub fn profile_digest() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PROFILE_DOMAIN);
    h.update(PROFILE_DESCRIPTOR);
    for domain in [
        ADMISSION_DOMAIN,
        DESCRIPTOR_DOMAIN,
        TERMINAL_DOMAIN,
        TERMINAL_SLOT_DOMAIN,
        SESSION_KEY_BINDING_DOMAIN,
        TENANT_SCOPE_PARTITION_DOMAIN,
        PROVIDER_FENCE_BINDING_DOMAIN,
        PUBLICATION_ID_DOMAIN,
        PUBLICATION_PAYLOAD_DOMAIN,
        PUBLICATION_EVIDENCE_DOMAIN,
        ADMISSION_FRAME_DOMAIN,
        TERMINAL_FRAME_DOMAIN,
        COMMITTED_TERMINAL_FRAME_DOMAIN,
        TOMBSTONE_FRAME_DOMAIN,
        TOMBSTONE_TERMINAL_INDEX_BINDING_DOMAIN,
        TOMBSTONE_ADMISSION_OWNER_COMMITMENT_DOMAIN,
        HISTORY_FLOOR_FRAME_DOMAIN,
        PROOF_DOMAIN,
        EXECUTOR_EVIDENCE_DOMAIN,
        TERMINAL_COMMITTING_GUARD_DOMAIN,
        TERMINAL_RECORD_COMMITMENT_DOMAIN,
        TERMINAL_RECEIPT_COMMITMENT_DOMAIN,
        PROVIDER_SCHEDULING_DOMAIN,
        PROOF_BINDING_DOMAIN,
        PROOF_DESCRIPTOR_DOMAIN,
        PROOF_OWNER_DOMAIN,
        PROOF_CREDENTIAL_DOMAIN,
        ROSTER_ATTESTATION_ROOT_DOMAIN,
        ROSTER_ATTESTATION_CERTIFICATE_DOMAIN,
        ROSTER_ATTESTATION_PROOF_DOMAIN,
        ROSTER_ATTESTATION_PROVIDER_RECEIPT_DOMAIN,
        ROSTER_ATTESTATION_STABLE_PROOF_DOMAIN,
        ROSTER_ATTESTATION_EVIDENCE_DOMAIN,
        ROSTER_ATTESTATION_BUNDLE_DOMAIN,
        ROSTER_INGRESS_ATTESTATION_DOMAIN,
        ROSTER_INGRESS_CAPSULE_DOMAIN,
        ROSTER_COMPACT_ADMISSION_PROVENANCE_DOMAIN,
        ROSTER_COMPACT_ADMISSION_COMMITMENT_DOMAIN,
        ROSTER_COMPACT_ADMISSION_FIELD_DOMAIN,
        ROSTER_COMPACT_ADMISSION_SLOT_DOMAIN,
        ROSTER_COMPACT_TERMINAL_EVIDENCE_DOMAIN,
        ROSTER_COMPACT_TERMINAL_COMMITMENT_DOMAIN,
    ] {
        h.update(domain);
    }
    h.update(ADMISSION_FRAME_MAGIC);
    h.update(TERMINAL_FRAME_MAGIC);
    h.update(COMMITTED_TERMINAL_FRAME_MAGIC);
    h.update(TOMBSTONE_FRAME_MAGIC);
    h.update(HISTORY_FLOOR_FRAME_MAGIC);
    h.update(ROSTER_ATTESTATION_PROVIDER_RECEIPT_MAGIC);
    h.update([
        PROVIDER_OPERATION_EXECUTE_TAG,
        PROVIDER_OPERATION_STATUS_TAG,
        PROVIDER_OPERATION_ADOPT_TAG,
        PROVIDER_OPERATION_COMPENSATE_TAG,
        PROVIDER_OPERATION_PREPARE_TAG,
        PROVIDER_OPERATION_RECONCILE_TAG,
    ]);
    h.update([PHASE_ESTABLISHED, PHASE_ABORTED]);
    h.update((ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES as u64).to_be_bytes());
    h.update((ROSTER_ATTESTATION_P256_SIGNATURE_BYTES as u64).to_be_bytes());
    h.update((MAX_EXECUTOR_PROOF_EVIDENCE_BYTES as u64).to_be_bytes());
    h.update((MAX_EXECUTOR_PROOF_BUNDLE_BYTES as u64).to_be_bytes());
    h.update((MAX_COMPACT_TERMINAL_EVIDENCE_BYTES as u64).to_be_bytes());
    h.update([
        ESTABLISHED_MUTATION_PUT_CHECKPOINT,
        ESTABLISHED_MUTATION_DELETE,
        ESTABLISHED_MUTATION_NO_OP,
    ]);
    h.update([
        PROVIDER_NOT_TRANSMITTED,
        PROVIDER_OUTCOME_UNKNOWN,
        PROVIDER_NOT_FOUND,
        PROVIDER_PENDING,
        PROVIDER_CONCLUSIVE,
        PROVIDER_PREPARED_NOT_RUN,
        PROVIDER_READY_TO_PREPARE,
    ]);
    h.update([
        PUBLICATION_OPERATION_STATUS_TAG,
        PUBLICATION_OPERATION_BEGIN_INTENT_TAG,
        PUBLICATION_OPERATION_ADOPT_TAG,
    ]);
    h.update([
        PUBLICATION_ABSENT,
        PUBLICATION_NOT_TRANSMITTED,
        PUBLICATION_OUTCOME_UNKNOWN,
        PUBLICATION_PENDING,
        PUBLICATION_PUBLISHED,
        PUBLICATION_CONFLICT,
    ]);
    h.update([
        OUTCOME_APPLIED_EXECUTED,
        OUTCOME_APPLIED_ADOPTED,
        OUTCOME_NOT_APPLIED_RECONCILED,
        OUTCOME_COMPENSATED_RECONCILED,
    ]);
    h.update(CONSUMER_ALPN);
    h.finalize().into()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
/// Stable opaque identity of one roster.
pub struct RosterId([u8; ROSTER_ID_BYTES]);
impl RosterId {
    /// Construct a roster identity from nonzero fixed-width bytes.
    pub fn from_bytes(bytes: [u8; ROSTER_ID_BYTES]) -> Result<Self, Error> {
        if bytes == [0; ROSTER_ID_BYTES] {
            Err(Error::InvalidRosterId)
        } else {
            Ok(Self(bytes))
        }
    }
    /// Return the fixed-width bytes of this identity.
    pub const fn as_bytes(&self) -> &[u8; ROSTER_ID_BYTES] {
        &self.0
    }
}
impl fmt::Debug for RosterId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RosterId(<redacted>)")
    }
}
impl<'de> Deserialize<'de> for RosterId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::from_bytes(<[u8; ROSTER_ID_BYTES]>::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// Nominal stable identity of exactly one provider operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct MemberOperationId([u8; MEMBER_OPERATION_ID_BYTES]);
impl MemberOperationId {
    /// Construct a member-operation identity from nonzero fixed-width bytes.
    pub fn from_bytes(bytes: [u8; MEMBER_OPERATION_ID_BYTES]) -> Result<Self, Error> {
        if bytes == [0; MEMBER_OPERATION_ID_BYTES] {
            Err(Error::InvalidMember)
        } else {
            Ok(Self(bytes))
        }
    }
    /// Return the fixed-width bytes of this identity.
    pub const fn as_bytes(&self) -> &[u8; MEMBER_OPERATION_ID_BYTES] {
        &self.0
    }
}
impl fmt::Debug for MemberOperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemberOperationId(<redacted>)")
    }
}
impl<'de> Deserialize<'de> for MemberOperationId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::from_bytes(<[u8; MEMBER_OPERATION_ID_BYTES]>::deserialize(d)?)
            .map_err(serde::de::Error::custom)
    }
}

/// Authenticated scope; it is neither deserializable nor public authority.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub(crate) struct Scope([u8; 32]);
impl Scope {
    pub(crate) const fn from_digest(digest: [u8; 32]) -> Self {
        Self(digest)
    }
    pub(crate) const fn digest(self) -> [u8; 32] {
        self.0
    }
    fn validate(self) -> Result<(), Error> {
        if self.0 == [0; 32] {
            Err(Error::InvalidAuthority)
        } else {
            Ok(())
        }
    }
}
impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scope(<redacted>)")
    }
}

/// One immutable ordered opaque provider effect.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Member {
    ordinal: u8,
    operation_id: MemberOperationId,
    descriptor: Vec<u8>,
    expected_version: u64,
}
impl Member {
    /// Construct one ordered opaque provider effect.
    ///
    /// `descriptor` is the caller/provider contract's already-canonical opaque
    /// byte representation. The SDK never calls an adapter before admission to
    /// reinterpret it. It must be nonempty and no larger than
    /// [`MAX_DESCRIPTOR_BYTES`].
    pub fn new(
        ordinal: u8,
        operation_id: MemberOperationId,
        descriptor: Vec<u8>,
        expected_version: u64,
    ) -> Result<Self, Error> {
        if descriptor.is_empty() || descriptor.len() > MAX_DESCRIPTOR_BYTES {
            return Err(Error::DescriptorTooLarge);
        }
        if expected_version == 0 {
            return Err(Error::InvalidMember);
        }
        Ok(Self {
            ordinal,
            operation_id,
            descriptor,
            expected_version,
        })
    }
    /// Return this member's zero-based position in its roster.
    pub const fn ordinal(&self) -> u8 {
        self.ordinal
    }
    /// Return the stable identity used to correlate this provider operation.
    pub const fn operation_id(&self) -> MemberOperationId {
        self.operation_id
    }
    /// Return the opaque provider descriptor without interpreting it.
    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }
    /// Return the provider version expected when performing this effect.
    pub const fn expected_version(&self) -> u64 {
        self.expected_version
    }
    fn descriptor_commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DESCRIPTOR_DOMAIN);
        update_len_prefixed(&mut h, &self.descriptor);
        h.finalize().into()
    }
}
impl fmt::Debug for Member {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Member(<redacted>)")
    }
}
#[derive(Deserialize)]
struct MemberWire {
    ordinal: u8,
    operation_id: MemberOperationId,
    descriptor: BoundedBytes<MAX_DESCRIPTOR_BYTES>,
    expected_version: u64,
}
impl<'de> Deserialize<'de> for Member {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = MemberWire::deserialize(d)?;
        Self::new(
            w.ordinal,
            w.operation_id,
            w.descriptor.0,
            w.expected_version,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Immutable session-record mutation applied only by an Established terminal.
///
/// This is a caller-authored mutation template, not execution authority.  The
/// authenticated admission supplies the exact session key and expected current
/// generation. A higher-fence successor may authorize the same immutable
/// template and exact checkpoint bytes. Terminal apply preserves the immutable
/// admission owner and fence in the authoritative record and advances only the
/// durable per-key execution-fence floor to the separately validated current
/// guard. Takeover never rewrites or reseals the checkpoint. An Aborted terminal
/// never applies this mutation.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct EstablishedMutation {
    tag: u8,
    state_type: Option<StateType>,
}

impl EstablishedMutation {
    /// Put the exact protected checkpoint as the authoritative session record.
    ///
    /// The committed generation is the checked successor of the admission's
    /// expected generation. V1 fixes the record class to authoritative
    /// session and forbids expiry, so terminal success cannot become dependent
    /// on elapsed wall time. The exact admitted EnvelopeV1 checkpoint remains
    /// bound to the immutable logical owner, admission fence, successor
    /// generation, and state type; a higher current execution fence authorizes
    /// takeover but never rewrites or reseals those bytes.
    pub fn put_checkpoint(state_type: StateType) -> Self {
        Self {
            tag: ESTABLISHED_MUTATION_PUT_CHECKPOINT,
            state_type: Some(state_type),
        }
    }

    /// Delete the exact admitted session record on Established.
    pub const fn delete() -> Self {
        Self {
            tag: ESTABLISHED_MUTATION_DELETE,
            state_type: None,
        }
    }

    /// Apply no session-record mutation while retaining the terminal roster.
    pub const fn no_op() -> Self {
        Self {
            tag: ESTABLISHED_MUTATION_NO_OP,
            state_type: None,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        match (self.tag, self.state_type.as_ref()) {
            (ESTABLISHED_MUTATION_PUT_CHECKPOINT, Some(_))
            | (ESTABLISHED_MUTATION_DELETE | ESTABLISHED_MUTATION_NO_OP, None) => Ok(()),
            _ => Err(Error::InvalidEstablishedMutation),
        }
    }

    pub(crate) const fn tag(&self) -> u8 {
        self.tag
    }

    pub(crate) fn state_type(&self) -> Option<&StateType> {
        self.state_type.as_ref()
    }
}

impl fmt::Debug for EstablishedMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EstablishedMutation(<redacted>)")
    }
}

#[derive(Serialize, Deserialize)]
struct EstablishedMutationWire {
    tag: u8,
    state_type: Option<StateType>,
}

impl<'de> Deserialize<'de> for EstablishedMutation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = EstablishedMutationWire::deserialize(deserializer)?;
        let value = Self {
            tag: wire.tag,
            state_type: wire.state_type,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Public validated caller proposal. It intentionally carries no authority.
///
/// Authenticated scope and admission types are deliberately not part of the
/// public API, so a consumer cannot manufacture tenant or fence authority:
///
/// ```compile_fail
/// use opc_session_net::FencedMutationRosterAdmission;
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct AdmissionProposal {
    profile: Profile,
    roster_id: RosterId,
    members: Vec<Member>,
    established_mutation: EstablishedMutation,
    protected_plan: Vec<u8>,
    terminal_checkpoint: Vec<u8>,
    terminal_result: Vec<u8>,
}
impl AdmissionProposal {
    /// Construct a validated public proposal without authenticated authority.
    ///
    /// The proposal validates profile, member ordering and uniqueness, and all
    /// descriptor and protected-payload bounds; the SDK later authenticates it.
    pub fn new(
        profile: Profile,
        roster_id: RosterId,
        members: Vec<Member>,
        established_mutation: EstablishedMutation,
        protected_plan: Vec<u8>,
        terminal_checkpoint: Vec<u8>,
        terminal_result: Vec<u8>,
    ) -> Result<Self, Error> {
        validate_proposal(
            profile,
            &members,
            &established_mutation,
            &protected_plan,
            &terminal_checkpoint,
            &terminal_result,
        )?;
        Ok(Self {
            profile,
            roster_id,
            members,
            established_mutation,
            protected_plan,
            terminal_checkpoint,
            terminal_result,
        })
    }
    /// Return the validated profile selected by this proposal.
    pub const fn profile(&self) -> Profile {
        self.profile
    }
    /// Return this proposal's stable roster identity.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }
    /// Return the immutable members in provider invocation order.
    pub fn members(&self) -> &[Member] {
        &self.members
    }
    /// Return the immutable session mutation applied only by Established.
    pub const fn established_mutation(&self) -> &EstablishedMutation {
        &self.established_mutation
    }
    /// Return the opaque protected plan.
    pub fn protected_plan(&self) -> &[u8] {
        &self.protected_plan
    }
    /// Return the protected checkpoint retained in the terminal record.
    pub fn terminal_checkpoint(&self) -> &[u8] {
        &self.terminal_checkpoint
    }
    /// Return the protected result retained in the terminal record.
    pub fn terminal_result(&self) -> &[u8] {
        &self.terminal_result
    }
}
impl fmt::Debug for AdmissionProposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AdmissionProposal(<redacted>)")
    }
}
#[derive(Deserialize)]
struct ProposalWire {
    profile: Profile,
    roster_id: RosterId,
    members: BoundedVec<Member, MAX_MEMBERS>,
    established_mutation: EstablishedMutation,
    protected_plan: BoundedBytes<MAX_PLAN_BYTES>,
    terminal_checkpoint: BoundedBytes<MAX_CHECKPOINT_BYTES>,
    terminal_result: BoundedBytes<MAX_RESULT_BYTES>,
}
impl<'de> Deserialize<'de> for AdmissionProposal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = ProposalWire::deserialize(d)?;
        Self::new(
            w.profile,
            w.roster_id,
            w.members.0,
            w.established_mutation,
            w.protected_plan.0,
            w.terminal_checkpoint.0,
            w.terminal_result.0,
        )
        .map_err(serde::de::Error::custom)
    }
}

fn validate_proposal(
    profile: Profile,
    members: &[Member],
    established_mutation: &EstablishedMutation,
    plan: &[u8],
    checkpoint: &[u8],
    result: &[u8],
) -> Result<(), Error> {
    profile.validate()?;
    established_mutation.validate()?;
    if members.is_empty() || members.len() > MAX_MEMBERS {
        return Err(Error::MemberLimit);
    }
    if plan.len() > MAX_PLAN_BYTES {
        return Err(Error::PlanTooLarge);
    }
    if checkpoint.len() > MAX_CHECKPOINT_BYTES {
        return Err(Error::CheckpointTooLarge);
    }
    if established_mutation.tag() == ESTABLISHED_MUTATION_PUT_CHECKPOINT && checkpoint.is_empty() {
        return Err(Error::InvalidEstablishedMutation);
    }
    if result.len() > MAX_RESULT_BYTES {
        return Err(Error::ResultTooLarge);
    }
    let mut ids = BTreeSet::new();
    for (index, member) in members.iter().enumerate() {
        if member.ordinal as usize != index
            || member.expected_version == 0
            || !ids.insert(member.operation_id)
        {
            return Err(Error::InvalidMember);
        }
    }
    Ok(())
}

/// Authenticated durable admission. Only the store/executor may create it.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Admission {
    proposal: AdmissionProposal,
    key: SessionKey,
    scope: Scope,
    logical_owner: OwnerId,
    admission_fence: FenceToken,
    expected_generation: Generation,
}
impl Admission {
    pub(crate) fn authenticate(
        proposal: AdmissionProposal,
        key: SessionKey,
        scope: Scope,
        logical_owner: OwnerId,
        admission_fence: FenceToken,
        expected_generation: Generation,
    ) -> Result<Self, Error> {
        validate_proposal(
            proposal.profile,
            &proposal.members,
            &proposal.established_mutation,
            &proposal.protected_plan,
            &proposal.terminal_checkpoint,
            &proposal.terminal_result,
        )?;
        scope.validate()?;
        if admission_fence.get() == 0 {
            return Err(Error::InvalidAuthority);
        }
        if proposal.established_mutation.tag() == ESTABLISHED_MUTATION_PUT_CHECKPOINT
            && expected_generation.next().is_none()
        {
            return Err(Error::InvalidEstablishedMutation);
        }
        Ok(Self {
            proposal,
            key,
            scope,
            logical_owner,
            admission_fence,
            expected_generation,
        })
    }
    pub(crate) fn body_commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ADMISSION_DOMAIN);
        h.update(self.proposal.profile.digest());
        h.update(self.proposal.roster_id.as_bytes());
        update_len_prefixed(&mut h, &session_key_canonical_digest_input(&self.key));
        h.update(self.scope.digest());
        update_len_prefixed(&mut h, self.logical_owner.as_str().as_bytes());
        h.update(self.admission_fence.get().to_be_bytes());
        h.update(self.expected_generation.get().to_be_bytes());
        h.update((self.proposal.members.len() as u64).to_be_bytes());
        for member in &self.proposal.members {
            h.update([member.ordinal]);
            h.update(member.operation_id.as_bytes());
            h.update(member.descriptor_commitment());
            h.update(member.expected_version.to_be_bytes());
        }
        h.update([self.proposal.established_mutation.tag()]);
        match self.proposal.established_mutation.state_type() {
            Some(state_type) => {
                h.update([1]);
                update_len_prefixed(&mut h, state_type.as_str().as_bytes());
            }
            None => h.update([0]),
        }
        update_len_prefixed(&mut h, &self.proposal.protected_plan);
        update_len_prefixed(&mut h, &self.proposal.terminal_checkpoint);
        update_len_prefixed(&mut h, &self.proposal.terminal_result);
        h.finalize().into()
    }
    pub(crate) const fn profile(&self) -> Profile {
        self.proposal.profile
    }
    pub(crate) const fn roster_id(&self) -> RosterId {
        self.proposal.roster_id
    }
    pub(crate) fn members(&self) -> &[Member] {
        &self.proposal.members
    }
    pub(crate) const fn established_mutation(&self) -> &EstablishedMutation {
        &self.proposal.established_mutation
    }
    pub(crate) fn protected_plan(&self) -> &[u8] {
        &self.proposal.protected_plan
    }
    pub(crate) fn terminal_checkpoint(&self) -> &[u8] {
        &self.proposal.terminal_checkpoint
    }
    pub(crate) fn terminal_result(&self) -> &[u8] {
        &self.proposal.terminal_result
    }
    pub(crate) fn key(&self) -> &SessionKey {
        &self.key
    }
    pub(crate) const fn scope(&self) -> Scope {
        self.scope
    }
    pub(crate) fn logical_owner(&self) -> &OwnerId {
        &self.logical_owner
    }
    pub(crate) const fn admission_fence(&self) -> FenceToken {
        self.admission_fence
    }
    pub(crate) const fn expected_generation(&self) -> Generation {
        self.expected_generation
    }
    pub(crate) fn binding_key(&self, history_epoch: u64) -> Result<RequestBindingKey, Error> {
        request_binding_key(
            history_epoch,
            self.scope,
            &self.key,
            self.proposal.roster_id,
        )
    }
    pub(crate) fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        encode_frame(
            ADMISSION_FRAME_MAGIC,
            ADMISSION_FRAME_DOMAIN,
            self,
            MAX_ADMISSION_CODEC_BYTES,
        )
    }
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let admission: Self = decode_frame(
            bytes,
            ADMISSION_FRAME_MAGIC,
            ADMISSION_FRAME_DOMAIN,
            MAX_ADMISSION_CODEC_BYTES,
        )?;
        if admission.to_canonical_bytes()?.as_slice() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(admission)
    }
}
impl fmt::Debug for Admission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Admission(<redacted>)")
    }
}
#[derive(Deserialize)]
struct AdmissionWire {
    proposal: AdmissionProposal,
    key: SessionKey,
    scope: [u8; 32],
    logical_owner: OwnerId,
    admission_fence: FenceToken,
    expected_generation: Generation,
}
impl<'de> Deserialize<'de> for Admission {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = AdmissionWire::deserialize(d)?;
        Self::authenticate(
            w.proposal,
            w.key,
            Scope::from_digest(w.scope),
            w.logical_owner,
            w.admission_fence,
            w.expected_generation,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
/// Opaque durable binding for one admitted roster in its authenticated
/// tenant, scope, session, and history epoch.
///
/// Values are issued by the SDK at admission and cannot be constructed by a
/// consumer. They are safe to retain as lookup handles but intentionally do
/// not expose their tenant or session-key commitments.
pub struct RequestBindingKey {
    history_epoch: u64,
    scope: Scope,
    tenant_scope_partition: [u8; 32],
    session_key_commitment: [u8; 32],
    roster_id: RosterId,
}
impl RequestBindingKey {
    fn validate(self) -> Result<(), Error> {
        validate_history_epoch(self.history_epoch)?;
        self.scope.validate()?;
        if self.tenant_scope_partition == [0; 32] || self.session_key_commitment == [0; 32] {
            return Err(Error::InvalidHistory);
        }
        Ok(())
    }

    /// Return the fixed-width canonical durable lookup key without exposing
    /// its tenant, session, or roster commitments.
    pub(crate) fn to_bytes(self) -> [u8; 120] {
        let mut bytes = [0; 120];
        bytes[..8].copy_from_slice(&self.history_epoch.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.scope.digest());
        bytes[40..72].copy_from_slice(&self.tenant_scope_partition);
        bytes[72..104].copy_from_slice(&self.session_key_commitment);
        bytes[104..].copy_from_slice(self.roster_id.as_bytes());
        bytes
    }
}
impl fmt::Debug for RequestBindingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestBindingKey(<redacted>)")
    }
}
#[derive(Deserialize)]
struct RequestBindingKeyWire {
    history_epoch: u64,
    scope: [u8; 32],
    tenant_scope_partition: [u8; 32],
    session_key_commitment: [u8; 32],
    roster_id: RosterId,
}
impl<'de> Deserialize<'de> for RequestBindingKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RequestBindingKeyWire::deserialize(deserializer)?;
        let value = Self {
            history_epoch: wire.history_epoch,
            scope: Scope::from_digest(wire.scope),
            tenant_scope_partition: wire.tenant_scope_partition,
            session_key_commitment: wire.session_key_commitment,
            roster_id: wire.roster_id,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize)]
/// Opaque identity binding an admitted roster body to one history epoch.
pub struct RequestId {
    history_epoch: u64,
    roster_id: RosterId,
    body_commitment: [u8; 32],
}
impl RequestId {
    #[cfg(test)]
    pub(crate) fn bind(history_epoch: u64, admission: &Admission) -> Result<Self, Error> {
        validate_history_epoch(history_epoch)?;
        Ok(Self {
            history_epoch,
            roster_id: admission.roster_id(),
            body_commitment: admission.body_commitment(),
        })
    }
    pub(crate) fn validate_for(self, admission: &Admission) -> Result<(), Error> {
        if validate_history_epoch(self.history_epoch).is_err()
            || self.roster_id != admission.roster_id()
            || self.body_commitment != admission.body_commitment()
        {
            Err(Error::RequestConflict)
        } else {
            Ok(())
        }
    }
    /// Return the nonzero history epoch bound into this request identity.
    pub(crate) const fn history_epoch(self) -> u64 {
        self.history_epoch
    }
    /// Return the fixed-width canonical byte representation of this identity.
    pub(crate) fn to_bytes(self) -> [u8; 56] {
        let mut bytes = [0; 56];
        bytes[..8].copy_from_slice(&self.history_epoch.to_be_bytes());
        bytes[8..24].copy_from_slice(self.roster_id.as_bytes());
        bytes[24..].copy_from_slice(&self.body_commitment);
        bytes
    }

    pub(crate) fn terminal_slot_id(self, admission: &Admission) -> Result<TerminalSlotId, Error> {
        self.validate_for(admission)?;
        Ok(TerminalSlotId(command_id(
            TERMINAL_SLOT_DOMAIN,
            admission.binding_key(self.history_epoch)?,
        )))
    }
}
impl fmt::Debug for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestId(<redacted>)")
    }
}
#[derive(Deserialize)]
struct RequestIdWire {
    history_epoch: u64,
    roster_id: RosterId,
    body_commitment: [u8; 32],
}
impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = RequestIdWire::deserialize(d)?;
        if validate_history_epoch(w.history_epoch).is_err() || w.body_commitment == [0; 32] {
            return Err(serde::de::Error::custom(Error::InvalidHistory));
        }
        Ok(Self {
            history_epoch: w.history_epoch,
            roster_id: w.roster_id,
            body_commitment: w.body_commitment,
        })
    }
}

fn validate_history_epoch(history_epoch: u64) -> Result<(), Error> {
    if history_epoch == 0 || history_epoch > MAX_HISTORY_EPOCH {
        Err(Error::InvalidHistory)
    } else {
        Ok(())
    }
}

fn request_binding_key(
    history_epoch: u64,
    scope: Scope,
    key: &SessionKey,
    roster_id: RosterId,
) -> Result<RequestBindingKey, Error> {
    validate_history_epoch(history_epoch)?;
    scope.validate()?;
    let mut hasher = Sha256::new();
    hasher.update(SESSION_KEY_BINDING_DOMAIN);
    update_len_prefixed(&mut hasher, &session_key_canonical_digest_input(key));
    let mut partition_hasher = Sha256::new();
    partition_hasher.update(TENANT_SCOPE_PARTITION_DOMAIN);
    partition_hasher.update(scope.digest());
    update_len_prefixed(&mut partition_hasher, key.tenant.as_str().as_bytes());
    let binding = RequestBindingKey {
        history_epoch,
        scope,
        tenant_scope_partition: partition_hasher.finalize().into(),
        session_key_commitment: hasher.finalize().into(),
        roster_id,
    };
    binding.validate()?;
    Ok(binding)
}

fn command_id(domain: &[u8], binding: RequestBindingKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(binding.history_epoch.to_be_bytes());
    hasher.update(binding.scope.digest());
    hasher.update(binding.tenant_scope_partition);
    hasher.update(binding.session_key_commitment);
    hasher.update(binding.roster_id.as_bytes());
    hasher.finalize().into()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TerminalSlotId([u8; 32]);
impl TerminalSlotId {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl fmt::Debug for TerminalSlotId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TerminalSlotId(<redacted>)")
    }
}

/// The only authoritative terminal phases; canonical tags are fixed above.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    /// All member proofs establish an effect that may be published.
    Established,
    /// Complete SDK-owned proofs establish a nonpublishing terminal outcome.
    Aborted,
}
impl Phase {
    const fn tag(self) -> u8 {
        match self {
            Self::Established => PHASE_ESTABLISHED,
            Self::Aborted => PHASE_ABORTED,
        }
    }
    fn from_tag(tag: u8) -> Result<Self, Error> {
        match tag {
            PHASE_ESTABLISHED => Ok(Self::Established),
            PHASE_ABORTED => Ok(Self::Aborted),
            _ => Err(Error::InvalidTerminal),
        }
    }
}

/// Consensus terminal record; no caller disposition/adoption is authoritative.
///
/// The record is crate-owned and therefore cannot be decoded or constructed
/// by a consumer as a substitute for SDK-issued member proofs:
///
/// ```compile_fail
/// use opc_session_net::FencedMutationRosterTerminalRecord;
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TerminalRecord {
    scope: [u8; 32],
    request_id: RequestId,
    admission_commitment: [u8; 32],
    phase_tag: u8,
    proof_commitments: Vec<[u8; 32]>,
    protected_checkpoint: Vec<u8>,
    protected_result: Vec<u8>,
    body_commitment: [u8; 32],
}
impl TerminalRecord {
    pub(crate) fn new(
        admission: &Admission,
        request_id: RequestId,
        phase: Phase,
        proof_commitments: Vec<[u8; 32]>,
    ) -> Result<Self, Error> {
        request_id.validate_for(admission)?;
        let mut value = Self {
            scope: admission.scope().digest(),
            request_id,
            admission_commitment: admission.body_commitment(),
            phase_tag: phase.tag(),
            proof_commitments,
            protected_checkpoint: admission.terminal_checkpoint().to_vec(),
            protected_result: admission.terminal_result().to_vec(),
            body_commitment: [0; 32],
        };
        value.body_commitment = value.calculate_body_commitment();
        value.validate_for(admission)?;
        Ok(value)
    }
    pub(crate) fn validate_for(&self, admission: &Admission) -> Result<(), Error> {
        self.request_id.validate_for(admission)?;
        if self.scope != admission.scope().digest()
            || self.admission_commitment != admission.body_commitment()
            || self.proof_commitments.len() != admission.members().len()
            || self.proof_commitments.contains(&[0; 32])
            || self.protected_checkpoint != admission.terminal_checkpoint()
            || self.protected_result != admission.terminal_result()
            || self.body_commitment != self.calculate_body_commitment()
        {
            return Err(Error::InvalidTerminal);
        }
        Phase::from_tag(self.phase_tag)?;
        Ok(())
    }
    pub(crate) fn phase(&self) -> Result<Phase, Error> {
        Phase::from_tag(self.phase_tag)
    }
    pub(crate) const fn request_id(&self) -> RequestId {
        self.request_id
    }
    pub(crate) fn protected_checkpoint(&self) -> &[u8] {
        &self.protected_checkpoint
    }
    pub(crate) fn protected_result(&self) -> &[u8] {
        &self.protected_result
    }
    /// Immutable per-member stable proof commitments in ordinal order.
    /// These are already part of the validated terminal record and are used
    /// only to project the matching raw V1 member into compact V2 evidence.
    pub(crate) fn proof_commitments(&self) -> &[[u8; 32]] {
        &self.proof_commitments
    }
    pub(crate) const fn body_commitment(&self) -> [u8; 32] {
        self.body_commitment
    }
    pub(crate) fn to_canonical_bytes(&self, admission: &Admission) -> Result<Vec<u8>, Error> {
        self.validate_for(admission)?;
        encode_frame(
            TERMINAL_FRAME_MAGIC,
            TERMINAL_FRAME_DOMAIN,
            self,
            MAX_TERMINAL_CODEC_BYTES,
        )
    }
    fn calculate_body_commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(TERMINAL_DOMAIN);
        h.update(self.scope);
        h.update(self.request_id.to_bytes());
        h.update(self.admission_commitment);
        h.update([self.phase_tag]);
        h.update((self.proof_commitments.len() as u64).to_be_bytes());
        for proof in &self.proof_commitments {
            h.update(proof);
        }
        update_len_prefixed(&mut h, &self.protected_checkpoint);
        update_len_prefixed(&mut h, &self.protected_result);
        h.finalize().into()
    }
}
impl fmt::Debug for TerminalRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TerminalRecord(<redacted>)")
    }
}
#[derive(Deserialize)]
struct TerminalWire {
    scope: [u8; 32],
    request_id: RequestId,
    admission_commitment: [u8; 32],
    phase_tag: u8,
    proof_commitments: BoundedVec<[u8; 32], MAX_MEMBERS>,
    protected_checkpoint: BoundedBytes<MAX_CHECKPOINT_BYTES>,
    protected_result: BoundedBytes<MAX_RESULT_BYTES>,
    body_commitment: [u8; 32],
}
impl<'de> Deserialize<'de> for TerminalRecord {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let w = TerminalWire::deserialize(d)?;
        Ok(Self {
            scope: w.scope,
            request_id: w.request_id,
            admission_commitment: w.admission_commitment,
            phase_tag: w.phase_tag,
            proof_commitments: w.proof_commitments.0,
            protected_checkpoint: w.protected_checkpoint.0,
            protected_result: w.protected_result.0,
            body_commitment: w.body_commitment,
        })
    }
}

/// Least-authority provider invocation view, constructed only by the executor.
pub struct MemberCall<'a> {
    roster_id: RosterId,
    admission_commitment: [u8; 32],
    member: &'a Member,
    current_fence: FenceToken,
    current_lease_acquired_at: Timestamp,
    current_lease_expires_at: Timestamp,
    provider_proof_epoch: u64,
    provider_receipt_challenge: ProviderReceiptChallenge,
}

/// Opaque, exact-call challenge for the separately protected Provider host.
///
/// It commits the SDK's immutable registration/member binding, the current
/// authority, invoked operation, and proof epoch.  Application code cannot
/// construct or reinterpret it as a conclusive provider disposition.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProviderReceiptChallenge {
    bytes: [u8; 32],
    operation: RosterProviderOperationV1,
    proof_epoch: u64,
}

impl ProviderReceiptChallenge {
    pub(crate) const fn from_executor(
        bytes: [u8; 32],
        operation: RosterProviderOperationV1,
        proof_epoch: u64,
    ) -> Self {
        Self {
            bytes,
            operation,
            proof_epoch,
        }
    }

    /// Return the fixed opaque challenge sent to the protected Provider host.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Build the fixed P-256 prehash for a receipt emitted by a separately
    /// protected Provider leaf. This is an interoperability seam only: it
    /// cannot choose the call binding, mint a certificate, or sign anything.
    /// The executor and Q2 independently reconstruct this prehash and verify
    /// the root-certified Provider certificate, current authority lease, and
    /// signature before accepting the capsule.
    pub fn protected_provider_leaf_receipt_digest(
        &self,
        provider_subject_identity_commitment: [u8; 32],
        outcome: RosterProviderOutcomeV1,
        evidence: &[u8],
    ) -> Result<[u8; 32], Error> {
        opc_session_store::fenced_mutation_roster::provider_receipt_digest_from_challenge_v1(
            self.bytes,
            provider_subject_identity_commitment,
            self.proof_epoch,
            self.operation,
            outcome,
            evidence,
        )
        .map_err(|_| Error::InvalidProviderEvidence)
    }

    /// Canonically assemble a receipt signed by the protected Provider leaf
    /// for this exact SDK-issued call. Operation and proof epoch are frozen
    /// inside this challenge and therefore cannot be selected by application
    /// code at capsule assembly time.
    pub fn protected_provider_leaf_signed_capsule(
        &self,
        outcome: RosterProviderOutcomeV1,
        evidence: Vec<u8>,
        certificate: RosterAttestationLeafCertificatePartsV1,
        signature: [u8; 64],
    ) -> Result<ProviderReceiptCapsule, Error> {
        ProviderReceiptCapsule::from_protected_provider_leaf_signed_parts(
            self.operation,
            outcome,
            self.proof_epoch,
            evidence,
            certificate,
            signature,
        )
    }
}

impl fmt::Debug for ProviderReceiptChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderReceiptChallenge(<redacted>)")
    }
}
impl<'a> MemberCall<'a> {
    pub(crate) fn from_executor(
        admission: &Admission,
        member: &'a Member,
        current_fence: FenceToken,
        current_lease_acquired_at: Timestamp,
        current_lease_expires_at: Timestamp,
        provider_proof_epoch: u64,
        provider_receipt_challenge: ProviderReceiptChallenge,
    ) -> Self {
        Self {
            roster_id: admission.roster_id(),
            admission_commitment: admission.body_commitment(),
            member,
            current_fence,
            current_lease_acquired_at,
            current_lease_expires_at,
            provider_proof_epoch,
            provider_receipt_challenge,
        }
    }
    /// Return the roster identity for this provider invocation.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }
    /// Return the commitment binding this invocation to its admission.
    pub const fn admission_commitment(&self) -> [u8; 32] {
        self.admission_commitment
    }
    /// Return the member's invocation order within the roster.
    pub const fn ordinal(&self) -> u8 {
        self.member.ordinal()
    }
    /// Return the member's stable provider-operation identity.
    pub const fn operation_id(&self) -> MemberOperationId {
        self.member.operation_id()
    }
    /// Return the opaque provider descriptor for this invocation.
    pub fn descriptor(&self) -> &[u8] {
        self.member.descriptor()
    }
    /// Return the provider version expected for this invocation.
    pub const fn expected_version(&self) -> u64 {
        self.member.expected_version()
    }
    /// Return the current SDK-issued fencing token for this invocation.
    pub const fn current_fence(&self) -> FenceToken {
        self.current_fence
    }
    /// Return when the current SDK-authenticated execution lease was acquired.
    pub const fn current_lease_acquired_at(&self) -> Timestamp {
        self.current_lease_acquired_at
    }
    /// Return when the current SDK-authenticated execution lease expires.
    ///
    /// Providers must reject work at or after this bound and must still apply
    /// their monotonic fence check. The timestamp is evidence carried from the
    /// current lease guard; it is never a replacement for provider fencing.
    pub const fn current_lease_expires_at(&self) -> Timestamp {
        self.current_lease_expires_at
    }
    /// Return the opaque exact-call challenge for Provider receipt issuance.
    pub const fn provider_receipt_challenge(&self) -> ProviderReceiptChallenge {
        self.provider_receipt_challenge
    }
    /// Return the exact nonzero epoch that the protected Provider leaf must
    /// include in its receipt signature for this invocation.
    pub const fn provider_proof_epoch(&self) -> u64 {
        self.provider_proof_epoch
    }
    /// Validate that provider work is still inside the authenticated lease interval.
    ///
    /// The executor performs this check immediately before every provider call.
    /// Providers must also enforce the monotonically increasing
    /// [`Self::current_fence`] against their own durable resource state.
    pub fn validate_current_lease_at(&self, now: Timestamp) -> Result<(), Error> {
        if now < self.current_lease_acquired_at || now >= self.current_lease_expires_at {
            return Err(Error::InvalidAuthority);
        }
        Ok(())
    }
    /// Return the stable redaction-safe identity providers use for fence tracking.
    ///
    /// The commitment intentionally excludes `current_fence` so all lease
    /// successors for one exact roster/member resource share the same monotonic
    /// fence row. Tenant, scope, key, descriptor, and version are transitively
    /// bound by the authenticated admission commitment, preventing aliases in
    /// another roster or tenant from sharing authority.
    pub fn fence_binding_commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(PROVIDER_FENCE_BINDING_DOMAIN);
        h.update(self.roster_id.as_bytes());
        h.update(self.admission_commitment);
        h.update([self.member.ordinal]);
        h.update(self.member.operation_id.as_bytes());
        h.update(self.member.descriptor_commitment());
        h.update(self.member.expected_version.to_be_bytes());
        h.finalize().into()
    }
}
impl fmt::Debug for MemberCall<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MemberCall(<redacted>)")
    }
}

/// Stable identity of one exact Established publication.
///
/// The identity binds the immutable roster, admission, terminal body, and
/// terminal receipt. It intentionally excludes the replaceable current lease
/// guard so a strictly higher-fence successor can adopt the same provider-
/// local publication instead of creating a second effect.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicationId([u8; 32]);

impl PublicationId {
    fn bind(
        roster_id: RosterId,
        admission_commitment: [u8; 32],
        terminal_body_commitment: [u8; 32],
        receipt_commitment: [u8; 32],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(PUBLICATION_ID_DOMAIN);
        hasher.update(roster_id.as_bytes());
        hasher.update(admission_commitment);
        hasher.update(terminal_body_commitment);
        hasher.update(receipt_commitment);
        Self(hasher.finalize().into())
    }

    /// Return the fixed-width redaction-safe provider journal key.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationId(<redacted>)")
    }
}

/// Least-authority provider view of one exact Established publication.
///
/// Values are constructed only from an SDK terminal receipt. The stable
/// publication and payload commitments exclude the replaceable current guard;
/// every call nevertheless carries that guard and must pass the SDK's
/// backend-owned current-authority read immediately before and after provider
/// I/O.
pub struct EstablishedPublicationCall<'a> {
    publication_id: PublicationId,
    roster_id: RosterId,
    admission_commitment: [u8; 32],
    terminal_body_commitment: [u8; 32],
    receipt_commitment: [u8; 32],
    payload_commitment: [u8; 32],
    protected_checkpoint: &'a [u8],
    protected_result: &'a [u8],
    current_fence: FenceToken,
    current_lease_acquired_at: Timestamp,
    current_lease_expires_at: Timestamp,
    authority: &'a super::runtime::PublicationAuthority,
}

impl<'a> EstablishedPublicationCall<'a> {
    pub(crate) fn from_executor(
        authority: &'a super::runtime::PublicationAuthority,
        protected_checkpoint: &'a [u8],
        protected_result: &'a [u8],
    ) -> Result<Self, Error> {
        if protected_checkpoint.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::CheckpointTooLarge);
        }
        if protected_result.len() > MAX_RESULT_BYTES {
            return Err(Error::ResultTooLarge);
        }
        let current_authority = authority.current_authority();
        if current_authority.expires_at() <= current_authority.acquired_at() {
            return Err(Error::InvalidAuthority);
        }
        let publication_id = PublicationId::bind(
            authority.roster_id(),
            authority.admission_commitment(),
            authority.terminal_body_commitment(),
            authority.receipt_commitment(),
        );
        let mut hasher = Sha256::new();
        hasher.update(PUBLICATION_PAYLOAD_DOMAIN);
        hasher.update(publication_id.as_bytes());
        update_len_prefixed(&mut hasher, protected_checkpoint);
        update_len_prefixed(&mut hasher, protected_result);
        let payload_commitment = hasher.finalize().into();
        Ok(Self {
            publication_id,
            roster_id: authority.roster_id(),
            admission_commitment: authority.admission_commitment(),
            terminal_body_commitment: authority.terminal_body_commitment(),
            receipt_commitment: authority.receipt_commitment(),
            payload_commitment,
            protected_checkpoint,
            protected_result,
            current_fence: current_authority.fence(),
            current_lease_acquired_at: current_authority.acquired_at(),
            current_lease_expires_at: current_authority.expires_at(),
            authority,
        })
    }

    /// Return the stable provider-local publication identity.
    pub const fn publication_id(&self) -> PublicationId {
        self.publication_id
    }

    /// Return the stable caller-owned roster identity.
    pub const fn roster_id(&self) -> RosterId {
        self.roster_id
    }

    /// Return the exact immutable admission commitment.
    pub const fn admission_commitment(&self) -> [u8; 32] {
        self.admission_commitment
    }

    /// Return the exact Established terminal-body commitment.
    pub const fn terminal_body_commitment(&self) -> [u8; 32] {
        self.terminal_body_commitment
    }

    /// Return the commitment to the atomically stored Established receipt.
    pub const fn receipt_commitment(&self) -> [u8; 32] {
        self.receipt_commitment
    }

    /// Return the exact publication payload commitment.
    pub const fn payload_commitment(&self) -> [u8; 32] {
        self.payload_commitment
    }

    /// Return the byte-exact protected terminal checkpoint.
    pub fn protected_checkpoint(&self) -> &[u8] {
        self.protected_checkpoint
    }

    /// Return the byte-exact protected terminal result.
    pub fn protected_result(&self) -> &[u8] {
        self.protected_result
    }

    /// Return the current SDK-authenticated publication fence.
    pub const fn current_fence(&self) -> FenceToken {
        self.current_fence
    }

    /// Return when the current SDK-authenticated publication lease was acquired.
    pub const fn current_lease_acquired_at(&self) -> Timestamp {
        self.current_lease_acquired_at
    }

    /// Return when the current SDK-authenticated publication lease expires.
    pub const fn current_lease_expires_at(&self) -> Timestamp {
        self.current_lease_expires_at
    }

    /// Validate the provider call against a backend-authenticated logical time.
    pub fn validate_current_lease_at(&self, now: Timestamp) -> Result<(), Error> {
        if now < self.current_lease_acquired_at || now >= self.current_lease_expires_at {
            return Err(Error::InvalidAuthority);
        }
        Ok(())
    }

    pub(crate) const fn authority(&self) -> &super::runtime::PublicationAuthority {
        self.authority
    }
}

impl fmt::Debug for EstablishedPublicationCall<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EstablishedPublicationCall(<redacted>)")
    }
}

/// Bounded opaque proof returned by the startup-owned publication provider.
///
/// Construction binds the provider evidence to one exact publication identity
/// and payload. It is an observation, not caller publication authority; only
/// the SDK adapter can combine it with the pre/post current-authority reads.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicationEvidence {
    publication_id: PublicationId,
    payload_commitment: [u8; 32],
    evidence_commitment: [u8; 32],
}

impl PublicationEvidence {
    /// Bind nonempty bounded opaque provider evidence to an exact SDK call.
    pub fn new(call: &EstablishedPublicationCall<'_>, evidence: Vec<u8>) -> Result<Self, Error> {
        validate_status_bytes(&evidence)?;
        if evidence.is_empty() {
            return Err(Error::InvalidProviderEvidence);
        }
        let mut hasher = Sha256::new();
        hasher.update(PUBLICATION_EVIDENCE_DOMAIN);
        hasher.update(call.publication_id().as_bytes());
        hasher.update(call.payload_commitment());
        update_len_prefixed(&mut hasher, &evidence);
        Ok(Self {
            publication_id: call.publication_id(),
            payload_commitment: call.payload_commitment(),
            evidence_commitment: hasher.finalize().into(),
        })
    }

    /// Return the exact publication identity bound by this evidence.
    pub const fn publication_id(&self) -> PublicationId {
        self.publication_id
    }

    /// Return the exact protected payload commitment bound by this evidence.
    pub const fn payload_commitment(&self) -> [u8; 32] {
        self.payload_commitment
    }

    /// Return a stable opaque commitment to the provider's durable evidence.
    pub const fn evidence_commitment(&self) -> [u8; 32] {
        self.evidence_commitment
    }

    pub(crate) fn validate_for(&self, call: &EstablishedPublicationCall<'_>) -> Result<(), Error> {
        if self.publication_id != call.publication_id()
            || self.payload_commitment != call.payload_commitment()
            || self.evidence_commitment == [0; 32]
        {
            return Err(Error::InvalidProviderEvidence);
        }
        Ok(())
    }
}

impl fmt::Debug for PublicationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationEvidence(<redacted>)")
    }
}

/// Provider observation for one exact Established publication.
#[non_exhaustive]
pub enum PublicationProviderOutcome {
    /// No exact durable intent was found by this read.
    ///
    /// This is non-exclusionary after ambiguity. It never authorizes an
    /// external effect; an unclassified receipt may use it only to invoke the
    /// effect-free `begin_publication` operation for the same exact identity.
    Absent,
    /// The current effect-free intent-admission call provably did not transmit.
    NotTransmitted,
    /// Delivery or publication outcome is unknown; only status or adoption may follow.
    OutcomeUnknown,
    /// A durable publication intent exists but its outcome is not yet conclusive.
    Pending(PublicationEvidence),
    /// The exact protected payload is durably published.
    Published(PublicationEvidence),
    /// The stable identity is already bound to a different protected payload.
    Conflict,
}

impl fmt::Debug for PublicationProviderOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationProviderOutcome(<redacted>)")
    }
}

#[async_trait]
/// Provider-local durable publication adapter fixed at SDK startup.
///
/// Implementations key a durable intent/tombstone by [`PublicationId`] and
/// exact payload commitment, enforce monotonically increasing fences, and keep
/// a Published tombstone after roster payload retention ends. These operations
/// are outside roster consensus. `begin_publication` must atomically create or
/// recover only an inert durable intent and is forbidden from crossing the
/// external publication boundary. `adopt` is the sole operation that may
/// reconcile or finish that effect: it must durably mark the intent attempted
/// before external I/O and must never blind-run an indeterminate outcome.
/// `Absent` is non-exclusionary after ambiguity and never effect authority.
///
/// The provider's logical state is monotonic: `Absent -> Reserved -> Attempted
/// -> Published`, with `Conflict` sticky. Once Reserved exists, no operation
/// may return it to Absent or recreate it; compact storage is permitted only
/// while preserving the same logical state and exact identity. Attempted may
/// resend only when the provider itself retained transport-conclusive
/// NotTransmitted evidence for that exact attempted call. Every method must
/// atomically compare and raise a durable per-publication fence floor, reject
/// a lower or expired authority before I/O, and serialize that check with its
/// state transition so a stale pod cannot race a successor.
pub trait EstablishedPublicationProvider: Send + Sync + 'static {
    /// Provider-specific error whose contents never enter SDK diagnostics.
    type Error: Send;

    /// Read the exact durable publication state without creating an intent.
    async fn status(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error>;

    /// Atomically create or recover an inert exact durable intent.
    ///
    /// Implementations must not perform local promotion, replay activation,
    /// network output, or any other externally visible publication here.
    async fn begin_publication(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error>;

    /// Reconcile or finish an existing exact durable publication intent.
    ///
    /// Before any external I/O, implementations must durably transition the
    /// same ID/body intent to attempted. Successors may call this operation
    /// after ambiguity, so it must status/adopt rather than replay an effect.
    async fn adopt(
        &self,
        call: &EstablishedPublicationCall<'_>,
    ) -> Result<PublicationProviderOutcome, Self::Error>;
}

/// Provider-observed disposition of a member operation.
///
/// These states describe only the provider observation. They are not terminal
/// proofs and cannot authorize terminalization on their own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemberDisposition {
    /// The provider has not yet reached a conclusive disposition.
    Pending,
    /// The requested effect was applied.
    Applied,
    /// The requested effect was not applied.
    NotApplied,
    /// A compensating action left the requested effect not applied.
    Compensated,
    /// The provider cannot determine the member disposition.
    Indeterminate,
}

/// Provider-observed adoption state for a member operation.
///
/// These states describe only how a provider observation was reached. They
/// are not terminal proofs and cannot authorize terminalization on their own.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MemberAdoption {
    /// The observation has not been reconciled or otherwise concluded.
    Unreconciled,
    /// The provider executed the requested effect.
    Executed,
    /// The provider observed an already-applied effect that the executor may adopt.
    Adopted,
    /// The provider reconciled the member state.
    Reconciled,
}

/// Executor-private conclusive outcome derived from a validated provider observation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ProviderOutcome {
    /// The provider executed the requested effect and supplied conclusive evidence.
    AppliedExecuted,
    /// The SDK adopted conclusive evidence that the requested effect was already applied.
    AppliedAdopted,
    /// Reconciliation conclusively established that the requested effect was not applied.
    NotAppliedReconciled,
    /// Reconciliation conclusively established a compensating non-applied outcome.
    CompensatedReconciled,
}
impl ProviderOutcome {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::AppliedExecuted => OUTCOME_APPLIED_EXECUTED,
            Self::AppliedAdopted => OUTCOME_APPLIED_ADOPTED,
            Self::NotAppliedReconciled => OUTCOME_NOT_APPLIED_RECONCILED,
            Self::CompensatedReconciled => OUTCOME_COMPENSATED_RECONCILED,
        }
    }
}
/// Bounded opaque Provider-leaf receipt returned by a protected provider host.
///
/// The SDK deliberately exposes only canonical bytes here.  It does not offer
/// a constructor that accepts an `Applied`, `Executed`, or other conclusive
/// state.  A provider host obtains these bytes from its separately protected
/// Provider leaf after it has performed the exact descriptor-bound operation.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderReceiptCapsule(Vec<u8>);

impl ProviderReceiptCapsule {
    /// Accept one bounded canonical receipt capsule from a protected provider
    /// host.  This does not trust the bytes: the executor reconstructs and
    /// verifies the exact Provider signature before issuing a proof.
    pub fn from_canonical_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() || bytes.len() > MAX_PROVIDER_RECEIPT_CAPSULE_BYTES {
            return Err(Error::InvalidProviderEvidence);
        }
        Ok(Self(bytes))
    }

    /// Internal assembly behind the challenge-bound protected-host seam.
    fn from_protected_provider_leaf_signed_parts(
        operation: RosterProviderOperationV1,
        outcome: RosterProviderOutcomeV1,
        proof_epoch: u64,
        evidence: Vec<u8>,
        certificate: RosterAttestationLeafCertificatePartsV1,
        signature: [u8; 64],
    ) -> Result<Self, Error> {
        let receipt = ProviderReceipt {
            operation,
            outcome,
            proof_epoch,
            evidence,
            certificate,
            signature,
        };
        // Validate the exact bounded wire before returning it to the caller;
        // root and signature authority are intentionally checked by runtime.
        let wire = receipt.to_wire();
        ProviderReceipt::from_wire(wire.clone())?;
        let bytes = postcard::to_allocvec(&wire).map_err(|_| Error::InvalidProviderEvidence)?;
        Self::from_canonical_bytes(bytes)
    }

    pub(crate) fn decode(&self) -> Result<ProviderReceipt, Error> {
        let wire: ProviderReceiptWire =
            postcard::from_bytes(&self.0).map_err(|_| Error::InvalidProviderEvidence)?;
        let receipt = ProviderReceipt::from_wire(wire)?;
        let canonical = postcard::to_allocvec(&receipt.to_wire())
            .map_err(|_| Error::InvalidProviderEvidence)?;
        if canonical != self.0 {
            return Err(Error::InvalidProviderEvidence);
        }
        Ok(receipt)
    }
}

impl fmt::Debug for ProviderReceiptCapsule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProviderReceiptCapsule(<redacted>)")
    }
}

const MAX_PROVIDER_RECEIPT_CAPSULE_BYTES: usize = MAX_STATUS_BYTES + 1024;

#[derive(Clone)]
pub(crate) struct ProviderReceipt {
    pub(crate) operation: RosterProviderOperationV1,
    pub(crate) outcome: RosterProviderOutcomeV1,
    pub(crate) proof_epoch: u64,
    pub(crate) evidence: Vec<u8>,
    pub(crate) certificate: RosterAttestationLeafCertificatePartsV1,
    pub(crate) signature: [u8; 64],
}

#[derive(Clone, Serialize, Deserialize)]
struct ProviderReceiptWire {
    operation: RosterProviderOperationV1,
    outcome: RosterProviderOutcomeV1,
    proof_epoch: u64,
    evidence: Vec<u8>,
    certificate: ProviderCertificateWire,
    signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ProviderCertificateWire {
    root_id: [u8; 32],
    role: RosterAttestationCertificateRoleV1,
    configuration_identity: SessionConsensusIdentity,
    scope: [u8; 32],
    subject_identity_commitment: [u8; 32],
    leaf_epoch: u64,
    key_id: [u8; 32],
    not_before: Timestamp,
    not_after: Timestamp,
    public_key: Vec<u8>,
    root_signature: Vec<u8>,
}

impl ProviderReceipt {
    fn from_wire(wire: ProviderReceiptWire) -> Result<Self, Error> {
        let public_key: [u8; 33] = wire
            .certificate
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidProviderEvidence)?;
        let root_signature: [u8; 64] = wire
            .certificate
            .root_signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidProviderEvidence)?;
        let signature: [u8; 64] = wire
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidProviderEvidence)?;
        if wire.proof_epoch == 0
            || wire.evidence.is_empty()
            || wire.evidence.len() > MAX_STATUS_BYTES
            || wire.certificate.role != RosterAttestationCertificateRoleV1::Provider
            || wire.certificate.leaf_epoch == 0
            || wire.certificate.key_id == [0; 32]
            || wire.certificate.subject_identity_commitment == [0; 32]
            || wire.certificate.not_after <= wire.certificate.not_before
        {
            return Err(Error::InvalidProviderEvidence);
        }
        Ok(Self {
            operation: wire.operation,
            outcome: wire.outcome,
            proof_epoch: wire.proof_epoch,
            evidence: wire.evidence,
            certificate: RosterAttestationLeafCertificatePartsV1 {
                root_id: wire.certificate.root_id,
                role: wire.certificate.role,
                configuration_identity: wire.certificate.configuration_identity,
                scope: wire.certificate.scope,
                subject_identity_commitment: wire.certificate.subject_identity_commitment,
                leaf_epoch: wire.certificate.leaf_epoch,
                key_id: wire.certificate.key_id,
                not_before: wire.certificate.not_before,
                not_after: wire.certificate.not_after,
                public_key,
                root_signature,
            },
            signature,
        })
    }

    fn to_wire(&self) -> ProviderReceiptWire {
        ProviderReceiptWire {
            operation: self.operation,
            outcome: self.outcome,
            proof_epoch: self.proof_epoch,
            evidence: self.evidence.clone(),
            certificate: ProviderCertificateWire {
                root_id: self.certificate.root_id,
                role: self.certificate.role,
                configuration_identity: self.certificate.configuration_identity,
                scope: self.certificate.scope,
                subject_identity_commitment: self.certificate.subject_identity_commitment,
                leaf_epoch: self.certificate.leaf_epoch,
                key_id: self.certificate.key_id,
                not_before: self.certificate.not_before,
                not_after: self.certificate.not_after,
                public_key: self.certificate.public_key.to_vec(),
                root_signature: self.certificate.root_signature.to_vec(),
            },
            signature: self.signature.to_vec(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum ProviderEvidence {
    Empty,
    Bytes(Vec<u8>),
    Receipt(ProviderReceiptCapsule),
}
/// Bounded provider result; raw evidence storage is private.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderCallOutcome {
    tag: u8,
    evidence: ProviderEvidence,
}
impl ProviderCallOutcome {
    /// Report that the current provider call was definitely not transmitted.
    ///
    /// This permits retrying only the identical retained call which directly
    /// produced it. A status call's non-transmission says nothing about an
    /// earlier prepare or execute attempt.
    pub fn not_transmitted() -> Self {
        Self {
            tag: PROVIDER_NOT_TRANSMITTED,
            evidence: ProviderEvidence::Empty,
        }
    }
    /// Report that delivery or outcome is unknown.
    ///
    /// This does not prove the effect was not applied; use status or adoption
    /// rather than retrying execution.
    pub fn outcome_unknown() -> Self {
        Self {
            tag: PROVIDER_OUTCOME_UNKNOWN,
            evidence: ProviderEvidence::Empty,
        }
    }
    /// Report that no provider status was found.
    ///
    /// This does not prove the effect was not applied and does not permit an
    /// execution retry by itself.
    pub fn not_found() -> Self {
        Self {
            tag: PROVIDER_NOT_FOUND,
            evidence: ProviderEvidence::Empty,
        }
    }
    /// Report that the exact admitted member is durably retained and execution
    /// has definitely not started.
    ///
    /// The provider must atomically bind this observation to the complete
    /// [`MemberCall::fence_binding_commitment`] and advance its monotonic fence,
    /// so an older delayed prepare or execute can no longer cross. This proves
    /// only that the operation is prepared but not run. A recovered public
    /// member remains status/adopt-only: process loss never reconstructs
    /// execute authority from this observation. It is not a terminal proof.
    pub fn prepared_not_run() -> Self {
        Self {
            tag: PROVIDER_PREPARED_NOT_RUN,
            evidence: ProviderEvidence::Empty,
        }
    }
    /// Report the stronger exclusionary state that the exact member has neither
    /// been prepared nor executed and may be prepared under the current fence.
    ///
    /// Unlike [`Self::not_found`], this observation must exclude every delayed
    /// older-fence call. Providers unable to make that durable assertion must
    /// return `not_found`, `pending`, or `outcome_unknown` instead.
    pub fn ready_to_prepare() -> Self {
        Self {
            tag: PROVIDER_READY_TO_PREPARE,
            evidence: ProviderEvidence::Empty,
        }
    }
    /// Report bounded opaque evidence that the provider outcome remains pending.
    pub fn pending(evidence: Vec<u8>) -> Result<Self, Error> {
        validate_status_bytes(&evidence)?;
        Ok(Self {
            tag: PROVIDER_PENDING,
            evidence: ProviderEvidence::Bytes(evidence),
        })
    }
    /// Return an already-signed opaque Provider receipt capsule.
    ///
    /// This API intentionally accepts no caller-authored disposition or
    /// adoption enum.  The executor decodes the capsule only to reconstruct
    /// the Provider's signed preimage and rejects it unless it matches the
    /// exact SDK-issued call and allowed operation/outcome truth table.
    pub fn conclusive_receipt(receipt: ProviderReceiptCapsule) -> Self {
        Self {
            tag: PROVIDER_CONCLUSIVE,
            evidence: ProviderEvidence::Receipt(receipt),
        }
    }
    pub(crate) fn into_parts(self) -> ProviderCallOutcomeParts {
        match self.evidence {
            ProviderEvidence::Empty if self.tag == PROVIDER_NOT_TRANSMITTED => {
                ProviderCallOutcomeParts::NotTransmitted
            }
            ProviderEvidence::Empty if self.tag == PROVIDER_OUTCOME_UNKNOWN => {
                ProviderCallOutcomeParts::OutcomeUnknown
            }
            ProviderEvidence::Empty if self.tag == PROVIDER_NOT_FOUND => {
                ProviderCallOutcomeParts::NotFound
            }
            ProviderEvidence::Empty if self.tag == PROVIDER_PREPARED_NOT_RUN => {
                ProviderCallOutcomeParts::PreparedNotRun
            }
            ProviderEvidence::Empty if self.tag == PROVIDER_READY_TO_PREPARE => {
                ProviderCallOutcomeParts::ReadyToPrepare
            }
            ProviderEvidence::Bytes(bytes) if self.tag == PROVIDER_PENDING => {
                ProviderCallOutcomeParts::Pending(bytes)
            }
            ProviderEvidence::Receipt(receipt) if self.tag == PROVIDER_CONCLUSIVE => {
                ProviderCallOutcomeParts::Conclusive(receipt)
            }
            _ => ProviderCallOutcomeParts::Malformed,
        }
    }
}
pub(crate) enum ProviderCallOutcomeParts {
    NotTransmitted,
    OutcomeUnknown,
    NotFound,
    PreparedNotRun,
    ReadyToPrepare,
    Pending(Vec<u8>),
    Conclusive(ProviderReceiptCapsule),
    Malformed,
}
impl fmt::Debug for ProviderCallOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderCallOutcome(<redacted>)")
    }
}
fn validate_status_bytes(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_STATUS_BYTES {
        Err(Error::StatusTooLarge)
    } else {
        Ok(())
    }
}

#[async_trait]
/// Opaque provider adapter for one member operation.
///
/// Implementations must not infer authority from a descriptor and must treat
/// [`MemberCall`] values as the complete, SDK-issued invocation context.
/// For each exact member binding—roster and admission commitment, authenticated
/// scope and tenant, ordinal, stable operation identity, descriptor, and expected
/// version—they must atomically enforce monotonically increasing
/// [`MemberCall::current_fence`] values. If a higher-fence
/// [`Self::status`] or [`Self::adopt`] call yields
/// conclusive [`MemberDisposition::NotApplied`] or
/// [`MemberDisposition::Compensated`] evidence with
/// [`MemberAdoption::Reconciled`], a delayed lower-fence
/// [`Self::execute`] call must be rejected and must never later apply an effect.
/// The first conclusive logical outcome and evidence commitment are immutable
/// within each monotonic provider stage. The sole transition is an SDK-issued
/// `Applied -> Compensated + Reconciled` compensation for the same exact call;
/// after that transition, every later status or adopt under any successor
/// fence must return the final compensation outcome and canonical evidence
/// bytes (or bytes with that same stable evidence commitment). It must never
/// switch an Applied proof directly to NotApplied, or replace a final
/// compensation with stale Applied evidence. This provider-side durable
/// invariant lets a higher-fence successor rebuild the byte-exact terminal
/// body after a lost terminal reply without inventing state or changing phase.
/// Terminal member commitments deliberately exclude the execution fence so
/// that reconstruction remains byte-identical.
///
/// The conclusive operation/outcome matrix is fixed:
///
/// | Operation | Permitted signed conclusive outcome |
/// | --- | --- |
/// | `prepare` | none; only the durable pre-effect observation |
/// | `execute` | `Applied + Executed` |
/// | `status` | either applied outcome, `NotApplied + Reconciled`, or `Compensated + Reconciled` |
/// | `adopt` | `Applied + Adopted`, `NotApplied + Reconciled`, or `Compensated + Reconciled` |
/// | `compensate_member` | `Compensated + Reconciled` only |
/// | `reconcile_member` | `NotApplied + Reconciled` or `Compensated + Reconciled` |
///
/// Every other observation stays nonconclusive. In particular, `NotFound` is
/// never exclusionary and cannot authorize an execution retry or Aborted
/// terminal.
pub trait MemberProvider: Send + Sync + 'static {
    /// Provider-specific error returned while executing or observing an operation.
    type Error: Send;
    /// Durably retain the exact member request without crossing its external
    /// effect boundary.
    ///
    /// A successful fresh preparation returns
    /// [`ProviderCallOutcome::prepared_not_run`]. The provider journal must be
    /// keyed by the stable fence binding (which excludes the replaceable current
    /// fence) while atomically enforcing the current monotonic fence. This call
    /// is provider-local and must not write SDK consensus. A preparation never
    /// returns a conclusive terminal receipt: a prior effect must instead be
    /// re-observed through [`Self::status`] or [`Self::adopt`].
    async fn prepare(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error>;
    /// Attempt the requested effect exactly once when the executor permits it.
    ///
    /// Only a `not_transmitted` returned directly by this exact call permits
    /// another identical execute attempt. A later status observation remains
    /// status/adopt-only and never restores execute authority.
    async fn execute(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error>;
    /// Observe provider state after an unknown, pending, or otherwise unresolved result.
    ///
    /// A conclusive signed receipt may report the immutable applied outcome,
    /// `NotApplied + Reconciled`, or a final `Compensated + Reconciled`
    /// outcome. `NotFound` remains non-exclusionary and cannot restore direct
    /// execution authority.
    async fn status(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error>;
    /// Adopt a durable exact provider intent after an ambiguity boundary.
    ///
    /// This may return conclusive adopted-applied or provider-local reconciled
    /// non-applied/compensated evidence, but must never create a new member
    /// identity or blindly execute the effect. `NotFound` remains
    /// non-exclusionary and cannot restore direct execution authority.
    async fn adopt(&self, call: &MemberCall<'_>) -> Result<ProviderCallOutcome, Self::Error>;

    /// Reconcile one exact ambiguous member without replaying its effect.
    ///
    /// A conclusive response must be an opaque Provider receipt establishing
    /// only `NotApplied + Reconciled` or `Compensated + Reconciled`.  `NotFound`
    /// remains non-exclusionary and never restores execute authority.
    async fn reconcile_member(
        &self,
        _call: &MemberCall<'_>,
    ) -> Result<ProviderCallOutcome, Self::Error> {
        Ok(ProviderCallOutcome::outcome_unknown())
    }

    /// Compensate an SDK-proven applied exact member under the current fence.
    ///
    /// The SDK invokes this only after every roster member has a conclusive
    /// provider observation and at least one member is already conclusively
    /// non-applied or compensated, locking the roster into its aborting
    /// direction. Implementations must durably bind the same call identity
    /// before I/O and may report a conclusive result only as `Compensated +
    /// Reconciled`.
    /// The default delegates to `adopt`, which is fail-closed unless an older
    /// provider implementation independently reports that exact compensation.
    async fn compensate_member(
        &self,
        call: &MemberCall<'_>,
    ) -> Result<ProviderCallOutcome, Self::Error> {
        self.adopt(call).await
    }
}

/// Compact conflict binding retained after the exact terminal payload ages out.
///
/// This tombstone is retired only with the enclosing V2 history epoch. Age
/// alone therefore never reopens a stable roster ID for a different body.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TerminalConflictTombstone {
    scope: Scope,
    admission_body_commitment: [u8; 32],
    terminal_body_commitment: [u8; 32],
    admission_owner_commitment: [u8; 32],
    admission_fence: u64,
    expected_generation: u64,
    phase_tag: u8,
    /// Exact applied-log coordinate from the authenticated retained terminal.
    terminal_raft_log_index: u64,
    /// Domain-separated binding of this coordinate to the exact immutable
    /// admission and terminal identities.
    terminal_index_binding: [u8; 32],
}

fn tombstone_terminal_index_binding(
    profile: Profile,
    binding: RequestBindingKey,
    admission_body_commitment: [u8; 32],
    terminal_body_commitment: [u8; 32],
    admission_owner_commitment: [u8; 32],
    phase_tag: u8,
    terminal_raft_log_index: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOMBSTONE_TERMINAL_INDEX_BINDING_DOMAIN);
    hasher.update(profile.schema().to_be_bytes());
    hasher.update(profile.consumer_revision().to_be_bytes());
    hasher.update(profile.digest());
    hasher.update(binding.to_bytes());
    hasher.update(admission_body_commitment);
    hasher.update(terminal_body_commitment);
    hasher.update(admission_owner_commitment);
    hasher.update([phase_tag]);
    hasher.update(terminal_raft_log_index.to_be_bytes());
    hasher.finalize().into()
}

fn tombstone_admission_owner_commitment(profile: Profile, owner: &OwnerId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TOMBSTONE_ADMISSION_OWNER_COMMITMENT_DOMAIN);
    hasher.update(profile.schema().to_be_bytes());
    hasher.update(profile.consumer_revision().to_be_bytes());
    hasher.update(profile.digest());
    let owner = owner.as_str().as_bytes();
    let owner_length = u64::try_from(owner.len()).expect("owner identifier length is bounded");
    hasher.update(owner_length.to_be_bytes());
    hasher.update(owner);
    hasher.finalize().into()
}

/// Complete caller claim for one compacted terminal lookup.
///
/// The immutable admission provenance and replaceable current authority are
/// intentionally grouped so a recovery path cannot accidentally validate a
/// mix of values from distinct lookups or leases.
pub(crate) struct CompactedTerminalLookup<'a> {
    /// Retained-history epoch bound into the original admission request ID.
    pub(crate) history_epoch: u64,
    /// Exact protected session key claimed by the caller.
    pub(crate) key: &'a SessionKey,
    /// Stable caller-owned roster identity.
    pub(crate) roster_id: RosterId,
    /// Immutable owner from the original admission.
    pub(crate) original_owner: &'a OwnerId,
    /// Immutable fence from the original admission.
    pub(crate) original_admission_fence: FenceToken,
    /// Current successor authority fence.
    pub(crate) current_fence: FenceToken,
    /// Current successor authority generation.
    pub(crate) current_generation: Generation,
}

impl TerminalConflictTombstone {
    /// Test-only fixture constructor. Production compaction must retain the
    /// index minted by a committed terminal, never one derived from a request.
    #[cfg(test)]
    pub(crate) fn new(admission: &Admission, record: &TerminalRecord) -> Result<Self, Error> {
        Self::from_record_with_raft_log_index(
            admission,
            record,
            record.request_id().history_epoch(),
        )
    }

    #[cfg(test)]
    fn from_record_with_raft_log_index(
        admission: &Admission,
        record: &TerminalRecord,
        terminal_raft_log_index: u64,
    ) -> Result<Self, Error> {
        record.validate_for(admission)?;
        if terminal_raft_log_index == 0 {
            return Err(Error::InvalidHistory);
        }
        let binding_key = admission.binding_key(record.request_id().history_epoch())?;
        let admission_owner_commitment =
            tombstone_admission_owner_commitment(admission.profile(), admission.logical_owner());
        let value = Self {
            scope: binding_key.scope,
            admission_body_commitment: admission.body_commitment(),
            terminal_body_commitment: record.body_commitment(),
            admission_owner_commitment,
            admission_fence: admission.admission_fence().get(),
            expected_generation: admission.expected_generation().get(),
            phase_tag: record.phase()?.tag(),
            terminal_raft_log_index,
            terminal_index_binding: tombstone_terminal_index_binding(
                admission.profile(),
                binding_key,
                admission.body_commitment(),
                record.body_commitment(),
                admission_owner_commitment,
                record.phase()?.tag(),
                terminal_raft_log_index,
            ),
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate_admission(
        &self,
        history_epoch: u64,
        admission: &Admission,
    ) -> Result<CompactedTerminalStatus, Error> {
        let binding_key = admission.binding_key(history_epoch)?;
        self.validate_binding(binding_key)?;
        if self.admission_body_commitment != admission.body_commitment() {
            return Err(Error::RequestConflict);
        }
        if self.admission_owner_commitment
            != tombstone_admission_owner_commitment(admission.profile(), admission.logical_owner())
            || self.admission_fence != admission.admission_fence().get()
            || self.expected_generation != admission.expected_generation().get()
        {
            return Err(Error::RequestConflict);
        }
        Ok(CompactedTerminalStatus {
            phase: Phase::from_tag(self.phase_tag)?,
            terminal_body_commitment: self.terminal_body_commitment,
        })
    }

    /// Recompute the exact request binding from the row/index key without
    /// reconstructing the reclaimed admission body.
    pub(crate) fn validate_binding(&self, binding: RequestBindingKey) -> Result<(), Error> {
        self.validate()?;
        if self.scope != binding.scope
            || self.terminal_index_binding
                != tombstone_terminal_index_binding(
                    Profile::v1(),
                    binding,
                    self.admission_body_commitment,
                    self.terminal_body_commitment,
                    self.admission_owner_commitment,
                    self.phase_tag,
                    self.terminal_raft_log_index,
                )
        {
            return Err(Error::InvalidAuthority);
        }
        Ok(())
    }

    /// Validate a compacted replay lookup without retaining an admission body.
    pub(crate) fn validate_lookup(
        &self,
        lookup: CompactedTerminalLookup<'_>,
    ) -> Result<CompactedTerminalStatus, Error> {
        // The current authenticated ingress may belong to a successor
        // configuration. Historical scope is resolved only from the durable
        // tombstone, while the exact caller key and roster remain bound to it.
        let binding_key = request_binding_key(
            lookup.history_epoch,
            self.scope,
            lookup.key,
            lookup.roster_id,
        )?;
        self.validate_binding(binding_key)?;
        if self.admission_owner_commitment
            != tombstone_admission_owner_commitment(Profile::v1(), lookup.original_owner)
            || lookup.original_admission_fence.get() != self.admission_fence
            || lookup.current_fence.get() <= self.admission_fence
            || lookup.current_generation.get() != self.expected_generation
        {
            return Err(Error::InvalidAuthority);
        }
        Ok(CompactedTerminalStatus {
            phase: Phase::from_tag(self.phase_tag)?,
            terminal_body_commitment: self.terminal_body_commitment,
        })
    }

    pub(crate) fn to_canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        encode_frame(
            TOMBSTONE_FRAME_MAGIC,
            TOMBSTONE_FRAME_DOMAIN,
            &self,
            MAX_TOMBSTONE_CODEC_BYTES,
        )
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let value: Self = decode_frame(
            bytes,
            TOMBSTONE_FRAME_MAGIC,
            TOMBSTONE_FRAME_DOMAIN,
            MAX_TOMBSTONE_CODEC_BYTES,
        )?;
        value.validate()?;
        if value.to_canonical_bytes()? != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), Error> {
        self.scope.validate()?;
        if self.admission_body_commitment == [0; 32]
            || self.terminal_body_commitment == [0; 32]
            || self.admission_owner_commitment == [0; 32]
            || self.terminal_raft_log_index == 0
            || self.terminal_index_binding == [0; 32]
        {
            return Err(Error::InvalidHistory);
        }
        if self.admission_fence == 0 {
            return Err(Error::InvalidHistory);
        }
        Phase::from_tag(self.phase_tag)?;
        Ok(())
    }
}

impl fmt::Debug for TerminalConflictTombstone {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TerminalConflictTombstone(<redacted>)")
    }
}

#[derive(Deserialize)]
struct TerminalConflictTombstoneWire {
    scope: [u8; 32],
    admission_body_commitment: [u8; 32],
    terminal_body_commitment: [u8; 32],
    admission_owner_commitment: [u8; 32],
    admission_fence: u64,
    expected_generation: u64,
    phase_tag: u8,
    terminal_raft_log_index: u64,
    terminal_index_binding: [u8; 32],
}

impl<'de> Deserialize<'de> for TerminalConflictTombstone {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = TerminalConflictTombstoneWire::deserialize(deserializer)?;
        let value = Self {
            scope: Scope::from_digest(wire.scope),
            admission_body_commitment: wire.admission_body_commitment,
            terminal_body_commitment: wire.terminal_body_commitment,
            admission_owner_commitment: wire.admission_owner_commitment,
            admission_fence: wire.admission_fence,
            expected_generation: wire.expected_generation,
            phase_tag: wire.phase_tag,
            terminal_raft_log_index: wire.terminal_raft_log_index,
            terminal_index_binding: wire.terminal_index_binding,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Read-only replay status after exact terminal payload compaction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompactedTerminalStatus {
    phase: Phase,
    terminal_body_commitment: [u8; 32],
}

impl CompactedTerminalStatus {
    pub(crate) const fn phase(self) -> Phase {
        self.phase
    }

    pub(crate) const fn terminal_body_commitment(self) -> [u8; 32] {
        self.terminal_body_commitment
    }
}

impl fmt::Debug for CompactedTerminalStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompactedTerminalStatus(<redacted>)")
    }
}

struct BoundedBytes<const MAX: usize>(Vec<u8>);
impl<'de, const MAX: usize> Deserialize<'de> for BoundedBytes<MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<const MAX: usize>;
        impl<'de, const MAX: usize> Visitor<'de> for V<MAX> {
            type Value = BoundedBytes<MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "at most {MAX} bytes")
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                if v.len() > MAX {
                    Err(E::custom("bounded bytes"))
                } else {
                    Ok(BoundedBytes(v))
                }
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                self.visit_byte_buf(v.to_vec())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                while let Some(byte) = s.next_element()? {
                    if v.len() == MAX {
                        return Err(serde::de::Error::custom("bounded bytes"));
                    }
                    v.push(byte);
                }
                Ok(BoundedBytes(v))
            }
        }
        d.deserialize_byte_buf(V::<MAX>)
    }
}
struct BoundedVec<T, const MAX: usize>(Vec<T>);
impl<'de, T: Deserialize<'de>, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T, const MAX: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for V<T, MAX> {
            type Value = BoundedVec<T, MAX>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "at most {MAX} entries")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                while let Some(value) = s.next_element()? {
                    if v.len() == MAX {
                        return Err(serde::de::Error::custom("bounded sequence"));
                    }
                    v.push(value);
                }
                Ok(BoundedVec(v))
            }
        }
        d.deserialize_seq(V::<T, MAX>(PhantomData))
    }
}

fn update_len_prefixed(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

/// Rebuild the store's fixed key digest input from its public, validated key
/// components. This carries no lease or consensus authority.
pub(crate) fn session_key_canonical_digest_input(key: &SessionKey) -> Vec<u8> {
    let key_type = key.key_type.as_str();
    let mut out = Vec::with_capacity(
        (4 * std::mem::size_of::<u64>())
            + key.tenant.as_str().len()
            + key.nf_kind.as_str().len()
            + key_type.len()
            + key.stable_id.len(),
    );

    for component in [
        key.tenant.as_str().as_bytes(),
        key.nf_kind.as_str().as_bytes(),
        key_type.as_bytes(),
        key.stable_id.as_ref(),
    ] {
        out.extend_from_slice(&(component.len() as u64).to_be_bytes());
        out.extend_from_slice(component);
    }

    out
}
fn frame_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
pub(crate) fn encode_frame<T: Serialize>(
    magic: [u8; 8],
    domain: &[u8],
    value: &T,
    max: usize,
) -> Result<Vec<u8>, Error> {
    let body_size =
        postcard::experimental::serialized_size(value).map_err(|_| Error::InvalidEncoding)?;
    let body_end = FRAME_HEADER_BYTES
        .checked_add(body_size)
        .ok_or(Error::EncodingTooLarge)?;
    let total = body_end
        .checked_add(FRAME_DIGEST_BYTES)
        .ok_or(Error::EncodingTooLarge)?;
    if total > max || body_size > u32::MAX as usize {
        return Err(Error::EncodingTooLarge);
    }
    let mut out = vec![0; total];
    out[..8].copy_from_slice(&magic);
    out[8..10].copy_from_slice(&SCHEMA_V1.to_be_bytes());
    out[10..14].copy_from_slice(&(body_size as u32).to_be_bytes());
    postcard::to_slice(value, &mut out[FRAME_HEADER_BYTES..body_end])
        .map_err(|_| Error::InvalidEncoding)?;
    let digest = frame_digest(domain, &out[..body_end]);
    out[body_end..].copy_from_slice(&digest);
    Ok(out)
}
pub(crate) fn decode_frame<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    magic: [u8; 8],
    domain: &[u8],
    max: usize,
) -> Result<T, Error> {
    if bytes.len() < FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES
        || bytes.len() > max
        || bytes[..8] != magic
    {
        return Err(Error::InvalidEncoding);
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != SCHEMA_V1 {
        return Err(Error::UnsupportedVersion);
    }
    let body_len = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    let end = FRAME_HEADER_BYTES
        .checked_add(body_len)
        .ok_or(Error::EncodingTooLarge)?;
    if end
        .checked_add(FRAME_DIGEST_BYTES)
        .ok_or(Error::EncodingTooLarge)?
        != bytes.len()
        || frame_digest(domain, &bytes[..end]) != bytes[end..]
    {
        return Err(Error::InvalidEncoding);
    }
    let (value, rest) = postcard::take_from_bytes(&bytes[FRAME_HEADER_BYTES..end])
        .map_err(|_| Error::InvalidEncoding)?;
    if !rest.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    Ok(value)
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
/// Validation, capacity, encoding, or provider-evidence failure for a roster operation.
pub enum Error {
    /// Authenticated scope or fencing authority was invalid.
    InvalidAuthority,
    /// A roster identity was all zeroes or otherwise invalid.
    InvalidRosterId,
    /// A member was malformed, out of order, or duplicated.
    InvalidMember,
    /// The roster has no members or exceeds [`MAX_MEMBERS`].
    MemberLimit,
    /// A member descriptor was empty or exceeded [`MAX_DESCRIPTOR_BYTES`].
    DescriptorTooLarge,
    /// A protected plan exceeded [`MAX_PLAN_BYTES`].
    PlanTooLarge,
    /// A protected terminal checkpoint exceeded [`MAX_CHECKPOINT_BYTES`].
    CheckpointTooLarge,
    /// The Established-only session-record mutation template was malformed.
    InvalidEstablishedMutation,
    /// A protected terminal result exceeded [`MAX_RESULT_BYTES`].
    ResultTooLarge,
    /// Provider evidence exceeded [`MAX_STATUS_BYTES`].
    StatusTooLarge,
    /// Canonical encoding would exceed its profile-bound maximum.
    EncodingTooLarge,
    /// Canonical encoded data was malformed or failed authentication.
    InvalidEncoding,
    /// Canonical encoded data used an unsupported schema version.
    UnsupportedVersion,
    /// Provider evidence was absent where a conclusive outcome requires it.
    InvalidProviderEvidence,
    /// Provider disposition and adoption did not form a conclusive observation.
    InvalidProviderState,
    /// A terminal record was inconsistent with its authenticated admission.
    InvalidTerminal,
    /// A request identity did not bind to the supplied authenticated admission.
    RequestConflict,
    /// A profile did not match the sole supported capability descriptor.
    CapabilityMismatch,
    /// Durable history state or its epoch was invalid.
    InvalidHistory,
    /// The live-roster capacity is exhausted.
    LiveFull,
    /// The combined live and retained history capacity is exhausted.
    HistoryFull,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidAuthority => "invalid roster authority",
            Self::InvalidRosterId => "invalid roster identity",
            Self::InvalidMember => "invalid roster member",
            Self::MemberLimit => "roster member limit exceeded",
            Self::DescriptorTooLarge => "roster descriptor exceeds limit",
            Self::PlanTooLarge => "protected roster plan exceeds limit",
            Self::CheckpointTooLarge => "protected roster checkpoint exceeds limit",
            Self::InvalidEstablishedMutation => "invalid established roster mutation",
            Self::ResultTooLarge => "protected roster result exceeds limit",
            Self::StatusTooLarge => "provider status exceeds limit",
            Self::EncodingTooLarge => "roster encoding exceeds limit",
            Self::InvalidEncoding => "invalid roster encoding",
            Self::UnsupportedVersion => "unsupported roster encoding version",
            Self::InvalidProviderEvidence => "invalid provider evidence",
            Self::InvalidProviderState => "invalid provider state",
            Self::InvalidTerminal => "invalid roster terminal",
            Self::RequestConflict => "roster request conflict",
            Self::CapabilityMismatch => "roster capability mismatch",
            Self::InvalidHistory => "invalid roster history state",
            Self::LiveFull => "roster live capacity exhausted",
            Self::HistoryFull => "roster history capacity exhausted",
        })
    }
}
impl std::error::Error for Error {}

#[cfg(test)]
mod frozen_cross_crate_goldens {
    use super::*;
    use bytes::Bytes;
    use opc_consensus::{derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch};
    use opc_session_store::{
        consensus::SessionConsensusIdentity,
        fenced_mutation_roster::{
            RosterAttestationCertificateRoleV1, RosterAttestationLeafCertificatePartsV1,
            RosterProviderOperationV1, RosterProviderOutcomeV1,
        },
        FenceToken, Generation, OwnerId, SessionKey, SessionKeyType, StableId,
    };
    use opc_types::{NetworkFunctionKind, TenantId};
    use sha2::{Digest, Sha256};

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"key")).expect("bounded stable ID"),
        }
    }

    fn admission() -> Admission {
        let proposal = AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([7; ROSTER_ID_BYTES]).expect("nonzero roster ID"),
            (0..FRESH_ROSTER_MEMBERS)
                .map(|ordinal| {
                    Member::new(
                        ordinal as u8,
                        MemberOperationId::from_bytes(
                            [ordinal as u8 + 1; MEMBER_OPERATION_ID_BYTES],
                        )
                        .expect("nonzero member operation ID"),
                        vec![ordinal as u8 + 1],
                        1,
                    )
                    .expect("bounded member")
                })
                .collect(),
            EstablishedMutation::no_op(),
            vec![1],
            vec![2],
            vec![3],
        )
        .expect("bounded fresh proposal");
        Admission::authenticate(
            proposal,
            key(),
            Scope::from_digest([9; 32]),
            OwnerId::new("owner").expect("bounded owner"),
            FenceToken::new(1),
            Generation::new(1),
        )
        .expect("authenticated frozen admission")
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    #[test]
    fn net_and_store_member_version_contracts_match_for_every_bounded_width() {
        for width in 1..=MAX_MEMBERS {
            for expected_version in [0, 1, u64::MAX] {
                let mut net_members = Vec::with_capacity(width);
                let mut store_members = Vec::with_capacity(width);
                for ordinal in 0..width {
                    let id_bytes = [ordinal as u8 + 1; MEMBER_OPERATION_ID_BYTES];
                    let net_member = Member::new(
                        ordinal as u8,
                        MemberOperationId::from_bytes(id_bytes)
                            .expect("nonzero net member operation ID"),
                        vec![ordinal as u8 + 1],
                        expected_version,
                    );
                    let store_member = opc_session_store::FencedMutationRosterMember::new(
                        ordinal as u8,
                        opc_session_store::FencedMutationRosterMemberOperationId::from_bytes(
                            id_bytes,
                        )
                        .expect("nonzero store member operation ID"),
                        vec![ordinal as u8 + 1],
                        expected_version,
                    );
                    assert_eq!(
                        net_member.is_ok(),
                        store_member.is_ok(),
                        "net/store member validation must agree"
                    );
                    if expected_version == 0 {
                        assert_eq!(net_member, Err(Error::InvalidMember));
                        assert_eq!(
                            store_member,
                            Err(opc_session_store::FencedMutationRosterError::InvalidMember)
                        );
                    } else {
                        net_members.push(net_member.expect("supported net member version"));
                        store_members.push(store_member.expect("supported store member version"));
                    }
                }

                if expected_version != 0 {
                    assert_eq!(net_members.len(), width);
                    assert_eq!(store_members.len(), width);
                    assert!(net_members
                        .iter()
                        .all(|member| member.expected_version() == expected_version));
                    assert!(store_members
                        .iter()
                        .all(|member| member.expected_version() == expected_version));
                }
            }
        }
    }

    #[test]
    fn net_client_codec_matches_store_frozen_profile_admission_and_terminal_goldens() {
        // These are the store crate's frozen goldens. Keeping the net copy on
        // this exact corpus catches any client/server canonical-codec drift.
        assert_eq!(
            profile_digest(),
            [
                0x7c, 0x49, 0x24, 0x64, 0xa0, 0x8d, 0xb0, 0x8f, 0xde, 0x85, 0x21, 0x0b, 0xc8, 0xdb,
                0x00, 0x15, 0x68, 0x82, 0xef, 0x24, 0x50, 0x3b, 0x99, 0x77, 0x34, 0x28, 0xce, 0x24,
                0x1f, 0x87, 0x12, 0x6a,
            ]
        );
        assert_eq!(
            profile_digest(),
            opc_session_store::fenced_mutation_roster_profile_digest()
        );
        let admission = admission();
        let admission_frame = admission
            .to_canonical_bytes()
            .expect("canonical admission frame");
        assert_eq!(
            sha256(&admission_frame),
            [
                0xa0, 0xbc, 0x24, 0x32, 0x57, 0x4a, 0xe7, 0x6e, 0x30, 0x97, 0x2d, 0xd4, 0x9b, 0x47,
                0x28, 0x19, 0x23, 0xed, 0x4d, 0x87, 0x77, 0x69, 0xf4, 0xe7, 0x8a, 0x73, 0x83, 0x4d,
                0x68, 0x7f, 0xde, 0x06,
            ]
        );
        let terminal = TerminalRecord::new(
            &admission,
            RequestId::bind(4, &admission).expect("frozen terminal request ID"),
            Phase::Established,
            vec![[1; 32]; FRESH_ROSTER_MEMBERS],
        )
        .expect("bounded frozen terminal");
        let terminal_frame = terminal
            .to_canonical_bytes(&admission)
            .expect("canonical terminal frame");
        assert_eq!(
            sha256(&terminal_frame),
            [
                0x5b, 0xa8, 0x2b, 0x31, 0xe5, 0x0b, 0x15, 0x1b, 0x1f, 0xaa, 0xb1, 0xf4, 0x67, 0x24,
                0xc4, 0x91, 0xef, 0x25, 0x54, 0xa4, 0x49, 0xf0, 0xa3, 0x19, 0x14, 0xb8, 0xf3, 0x5f,
                0xef, 0x53, 0xf0, 0x11,
            ]
        );
    }

    #[test]
    fn tombstone_v3_rejects_old_frames_and_tampered_commitments() {
        let admission = admission();
        let terminal = TerminalRecord::new(
            &admission,
            RequestId::bind(4, &admission).expect("terminal request ID"),
            Phase::Established,
            vec![[1; 32]; FRESH_ROSTER_MEMBERS],
        )
        .expect("terminal");
        let tombstone =
            TerminalConflictTombstone::new(&admission, &terminal).expect("v3 tombstone");
        let canonical = tombstone.to_canonical_bytes().expect("v3 frame");
        assert_eq!(
            TerminalConflictTombstone::from_canonical_bytes(&canonical),
            Ok(tombstone.clone())
        );

        let old_frame = encode_frame(
            *b"OPCRTB2\0",
            b"opc/session-store/protected-roster/tombstone-frame/v2\0",
            &tombstone,
            MAX_TOMBSTONE_CODEC_BYTES,
        )
        .expect("old-version frame");
        assert_eq!(
            TerminalConflictTombstone::from_canonical_bytes(&old_frame),
            Err(Error::InvalidEncoding),
            "mixed old/new tombstone frames fail closed"
        );

        let mut rebound = tombstone.clone();
        rebound.terminal_raft_log_index += 1;
        let rebound_frame = encode_frame(
            TOMBSTONE_FRAME_MAGIC,
            TOMBSTONE_FRAME_DOMAIN,
            &rebound,
            MAX_TOMBSTONE_CODEC_BYTES,
        )
        .expect("rebound v3 frame");
        let rebound = TerminalConflictTombstone::from_canonical_bytes(&rebound_frame)
            .expect("structural decoder accepts a framed tombstone");
        assert_eq!(
            rebound.validate_binding(admission.binding_key(4).expect("binding")),
            Err(Error::InvalidAuthority),
            "the terminal index binding rejects a reframed changed index"
        );

        let mut changed_owner_commitment = tombstone;
        changed_owner_commitment.admission_owner_commitment[0] ^= 1;
        let changed_owner_commitment = encode_frame(
            TOMBSTONE_FRAME_MAGIC,
            TOMBSTONE_FRAME_DOMAIN,
            &changed_owner_commitment,
            MAX_TOMBSTONE_CODEC_BYTES,
        )
        .expect("owner-commitment tamper frame");
        let changed_owner_commitment =
            TerminalConflictTombstone::from_canonical_bytes(&changed_owner_commitment)
                .expect("structural decoder accepts owner-commitment tamper");
        assert_eq!(
            changed_owner_commitment.validate_admission(4, &admission),
            Err(Error::InvalidAuthority),
            "the owner commitment is bound into the terminal index binding"
        );
    }

    #[test]
    fn protected_provider_leaf_challenge_is_public_wire_free_and_call_bound() {
        let cluster = ConsensusClusterId::new("provider-capsule-test").expect("cluster ID");
        let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
        let configuration = derive_configuration_id(cluster, epoch, &[]);
        let now = Timestamp::now_utc();
        let certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: [1; 32],
            role: RosterAttestationCertificateRoleV1::Provider,
            configuration_identity: SessionConsensusIdentity::new(cluster, configuration, epoch),
            scope: [2; 32],
            subject_identity_commitment: [3; 32],
            leaf_epoch: 1,
            key_id: [4; 32],
            not_before: now.add_seconds(-60).expect("not before"),
            not_after: now.add_seconds(60).expect("not after"),
            public_key: [5; 33],
            root_signature: [6; 64],
        };
        let challenge =
            ProviderReceiptChallenge::from_executor([7; 32], RosterProviderOperationV1::Execute, 9);
        let evidence = b"protected-provider-evidence";
        let digest = challenge
            .protected_provider_leaf_receipt_digest(
                certificate.subject_identity_commitment,
                RosterProviderOutcomeV1::AppliedExecuted,
                evidence,
            )
            .expect("challenge-bound digest");
        let capsule = challenge
            .protected_provider_leaf_signed_capsule(
                RosterProviderOutcomeV1::AppliedExecuted,
                evidence.to_vec(),
                certificate,
                [8; 64],
            )
            .expect("opaque capsule without wire knowledge");
        assert_eq!(capsule.decode().expect("canonical capsule").proof_epoch, 9);
        assert_ne!(
            digest,
            ProviderReceiptChallenge::from_executor([7; 32], RosterProviderOperationV1::Status, 9,)
                .protected_provider_leaf_receipt_digest(
                    [3; 32],
                    RosterProviderOutcomeV1::AppliedExecuted,
                    evidence,
                )
                .expect("different operation digest"),
            "the protected host cannot replay a receipt under another call operation"
        );
    }
}
