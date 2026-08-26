//! Generic, bounded protected atomic-mutation roster contract.
//!
//! Provider I/O is deliberately outside consensus. This module owns only the
//! immutable proposal, its authenticated admission, and terminal persistence.

use crate::consensus::SessionConsensusIdentity;
use crate::fenced_mutation_roster_executor::{
    AuthorityBinding, AuthorityLeaseMetadata, BackendRegistration,
};
use crate::model::{FenceToken, Generation, OwnerId, SessionKey, StateType};
use opc_types::Timestamp;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{
    de::{SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt, marker::PhantomData, time::Duration};

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
/// Maximum provider evidence carried in one independently signed terminal
/// proof. This is intentionally the provider-status ceiling rather than a
/// terminal checkpoint/result limit.
pub const MAX_EXECUTOR_PROOF_EVIDENCE_BYTES: usize = MAX_STATUS_BYTES;
/// Exact P-256 SEC1 compressed public-key width.
pub const ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES: usize = 33;
/// Exact P-256 IEEE-P1363 `r || s` signature width.
pub const ROSTER_ATTESTATION_P256_SIGNATURE_BYTES: usize = 64;
/// Maximum retained canonical attestation-bundle bytes in a terminal command.
///
/// Eight 4096-byte evidence payloads plus fixed certificate/proof framing fit
/// below this ceiling; it remains independent of the 1 MiB checkpoint and
/// 16 KiB result limits.
pub const MAX_EXECUTOR_PROOF_BUNDLE_BYTES: usize = 40 * 1024;
/// Maximum canonical bytes of one ingress attestation statement.
pub const MAX_ROSTER_INGRESS_ATTESTATION_BYTES: usize = 1024;
/// Maximum canonical bytes retained for a root-verifiable compact admission.
///
/// This deliberately contains commitments only: it is sufficient to prove the
/// original immutable admission after its protected payload and descriptors
/// have been deterministically compacted, without retaining either.
pub const MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES: usize = 2048;
/// Maximum canonical bytes retained for compact terminal evidence.
///
/// Eight fixed-width signed member summaries, one root-certified leaf
/// certificate, and the common terminal binding fit below this limit. Raw
/// provider evidence is never carried here.
pub const MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES: usize = 8 * 1024;
/// Maximum number of live admitted rosters.
pub const MAX_LIVE_ROSTERS: usize = 1_024;
/// Maximum combined number of live and retained terminal rosters.
pub const MAX_RESERVED_AND_RETAINED: usize = 131_072;
/// Operational live-and-retained roster target committed by the profile.
pub(crate) const OPERATIONAL_TARGET: usize = 100_000;
/// Maximum number of eligible terminal records reclaimed in one batch.
pub const RECLAIM_BATCH: usize = 1_024;
/// Duration for which a terminal record remains retained after terminalization.
pub const TERMINAL_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
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
const TOMBSTONE_FRAME_DOMAIN: &[u8] = b"opc/session-store/protected-roster/tombstone-frame/v1\0";
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
const TOMBSTONE_FRAME_MAGIC: [u8; 8] = *b"OPCRTB1\0";
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
/// Dedicated provider-receipt domain.  This is deliberately distinct from
/// executor aggregation and never commits a selected terminal phase/body.
const ROSTER_ATTESTATION_PROVIDER_RECEIPT_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-attestation-provider-receipt/v1\0";
const ROSTER_ATTESTATION_PROVIDER_RECEIPT_MAGIC: [u8; 8] = *b"OPCPRC1\0";
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
// This is deliberately the pre-consensus roster-admission slot domain. It is
// stable before Raft assigns RequestBindingKey.history_epoch, unlike the
// post-apply terminal slot and registration binding.
const ROSTER_COMPACT_ADMISSION_SLOT_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/roster-admission-slot/v2\0";
const ROSTER_COMPACT_TERMINAL_EVIDENCE_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-compact-terminal-evidence/v2\0";
const ROSTER_COMPACT_TERMINAL_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/session-store/roster-compact-terminal-commitment/v2\0";

// `serde` only derives fixed arrays through 32 elements. Attestation keys and
// P1363 signatures intentionally exceed that, so retain exact-width canonical
// byte strings through these two bounded adapters rather than weakening the
// wire representation to unbounded vectors.
mod fixed_array_33 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 33], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 33], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid fixed attestation bytes"))
    }
}

mod fixed_array_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid fixed attestation bytes"))
    }
}

mod fixed_array_56 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 56], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 56], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid fixed attestation bytes"))
    }
}

mod fixed_array_120 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 120], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 120], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid fixed attestation bytes"))
    }
}
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
/// Fixed descriptor-bound maximum for an irreversible-history floor frame.
pub(crate) const MAX_HISTORY_FLOOR_CODEC_BYTES: usize = 128;
/// Deterministic roster-ledger logical/schema charge budget, not a raw
/// SQLite or global-store capacity cap.
pub(crate) const PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES: u64 = 256 * 1024 * 1024 * 1024;
/// Frozen version of the deterministic roster charge witness.
pub(crate) const CHARGE_WITNESS_VERSION: u8 = 1;
/// Page unit used by deterministic aggregate snapshot-charge accounting.
pub(crate) const STORAGE_CHARGE_PAGE_BYTES: u64 = 4_096;
/// Fixed logical live-row overhead charged per roster.
pub(crate) const STORAGE_CHARGE_LIVE_ROW_BYTES: u64 = 512;
/// Fixed logical retained-row overhead charged per roster.
pub(crate) const STORAGE_CHARGE_RETAINED_ROW_BYTES: u64 = 384;
/// Fixed logical tombstone-row overhead charged per roster.
pub(crate) const STORAGE_CHARGE_TOMBSTONE_ROW_BYTES: u64 = 128;
/// Fixed logical live-index overhead charged per roster.
pub(crate) const STORAGE_CHARGE_LIVE_INDEX_BYTES: u64 = 192;
/// Fixed logical retained-index overhead charged per roster.
pub(crate) const STORAGE_CHARGE_RETAINED_INDEX_BYTES: u64 = 160;
/// Fixed logical tombstone-index overhead charged per roster.
pub(crate) const STORAGE_CHARGE_TOMBSTONE_INDEX_BYTES: u64 = 96;
/// Conservative receipt/header overhead beyond its separately charged record.
pub(crate) const MAX_COMPOSITE_RECEIPT_OVERHEAD_BYTES: usize = 4_096;
/// Conservative authoritative-session header overhead beyond checkpoint bytes.
pub(crate) const MAX_BUSINESS_SESSION_HEADER_BYTES: usize = 4_096;

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
    "domains=profile,admission,descriptor,terminal,terminal-slot,session-key-binding,tenant-scope-partition,provider-fence-binding,publication-id,publication-payload,publication-evidence,admission-frame,terminal-frame,committed-terminal-frame,tombstone-frame,history-floor-frame,executor-proof,executor-evidence,terminal-committing-guard,terminal-session-record,terminal-receipt,provider-scheduling,binding,descriptor,owner,credential,roster-attestation-root,roster-attestation-certificate,roster-attestation-proof,roster-attestation-provider-receipt,roster-attestation-stable-proof,roster-attestation-evidence,roster-attestation-bundle,roster-ingress-attestation,roster-ingress-capsule\n",
    "magics=OPCRAD2\\0,OPCRTM2\\0,OPCRCT1\\0,OPCRTB1\\0,OPCRHF1\\0,OPCPRC1\\0\n",
    "field-order=profile,roster,members,established-mutation,plan,checkpoint,result;key,scope,owner,fence,generation;binding:epoch,scope,tenant-scope-partition,session-key-commitment,roster-id;tombstone:binding,admission-commitment,terminal-commitment,admission-owner,admission-fence,generation,phase;history-floor:scope,tenant-scope-partition,retired-through\n",
    "executor-field-order=proof-binding:roster-attestation-proof,profile,configuration-identity,certificate-subject,certificate-role,binding,registration-handle,registration-request-id,terminal-slot,roster-id,admission-commitment,terminal-phase,terminal-body-commitment,ordinal,stable-member-operation-id,descriptor-length,descriptor,descriptor-commitment,expected-version,expected-generation,scope,key,owner-commitment,fence,credential-commitment,generation,acquired-at-nanos,expires-at-nanos,proof-epoch,operation,outcome,evidence-length,evidence,evidence-commitment;provider-receipt=roster-attestation-provider-receipt,profile,configuration-identity,provider-certificate-subject,provider-role,binding,registration-handle,registration-request-id,terminal-slot,roster-id,admission-commitment,ordinal,stable-member-operation-id,descriptor-length,descriptor,descriptor-commitment,expected-version,expected-generation,scope,key,owner-commitment,fence,credential-commitment,generation,acquired-at-nanos,expires-at-nanos,proof-epoch,operation,outcome,evidence-length,evidence,evidence-commitment;proof-commitment:roster-attestation-stable-proof,binding,registration-request-id,terminal-slot,roster-id,admission-commitment,phase,ordinal,stable-member-operation-id,descriptor-length,descriptor,descriptor-commitment,expected-version,expected-generation,outcome,evidence-commitment;certificate=roster-attestation-certificate,version,root-id,role,configuration-identity,scope,subject,leaf-epoch,key-id[32],not-before,not-after,compressed-p256-key;attestation=p256-sha256,compressed-sec1:33,low-s-p1363:64,roles:executor|provider|transport-ingress;ingress=roster-ingress-attestation,profile-alpn,peer,scope,request,operation,capsule,authenticated-at,peer-cert-expires,material-generation,handshake-epoch;provider-operations=local-prepare-execute-status-adopt-compensate-reconcile\n",
    "committed-terminal-frame-field-order=record,commit-metadata(sequence,raft-log-index,committed-at),committing-registration-handle,committing-registration-request-id,committing-registration-terminal-slot-id,committing-authority-scope,committing-authority-key,committing-authority-owner,committing-authority-fence,committing-authority-credential,committing-authority-generation,committing-authority-acquired-at,committing-authority-expires-at,committing-guard-commitment,materialization,receipt-commitment;materialization-postcard-tags=updated:0,deleted:1,no-op:2,aborted:3\n",
    "terminal-guard-field-order=profile,committing-registration-handle,committing-registration-request-id,committing-registration-terminal-slot-id,admission-commitment,scope,key,owner,fence,credential,generation,acquired-at,expires-at\n",
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
    "limits=max-members:8,accepted-members:1..8,fresh-target-members:6,plan:1048576,checkpoint:1048576,result:16384,roster-id:16,member-operation-id:16,descriptor:16384,status:4096,attestation-evidence:4096,attestation-bundle:40960,compact-terminal-evidence:8192,ingress-attestation:1024,admission-codec:2245658,terminal-codec:1065423,committed-terminal-codec:1069519,tombstone-codec:256,history-floor-codec:128,history-epoch-max:9223372036854775807,live:1024,live-plus-retained:131072,epoch-bindings:131072,operational-target:100000,reclaim:1024,retention-seconds:86400,quorum-mutations:fresh-success=2(admission,terminalization);remote-reads=admission-status,recover,terminal-status,current-publication-authority;local-authority-checks=provider-pre-post,publication-pre-post\n",
    "maintenance=bounded-deterministic-reclaim-and-retirement,payload-compaction,irreversible-floor-retirement;never-on-fresh-success;local-provider-journal-only\n",
    "history=stable-slot-binds-epoch-scope-session-key-roster-id,new-v2-admission-atomically-selects-binds-current-epoch-greater-than-durable-exact-scope-floor-before-reserve,admit-reserves-one-terminal-slot,terminal-retention-starts-at-terminalization,reclaim-oldest-min-1024-eligible-to-v2-conflict-tombstone,never-reclaim-live,durable-canonical-scope-bound-irreversible-floor,never-reopen-before-scope-bound-irreversible-epoch-retirement\n",
    "retry=prepare-or-execute-only-after-same-call-not-transmitted,outcome-unknown-status-adopt-only,not-found-non-exclusionary\n",
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
    h.update((MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES as u64).to_be_bytes());
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
    pub(crate) fn descriptor_commitment(&self) -> [u8; 32] {
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
/// use opc_session_store::fenced_mutation_roster::{Admission, Scope};
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
    /// Derived from the immutable wire fields during authenticated
    /// construction/deserialization. This is deliberately absent from the
    /// canonical wire shape: terminal proof verification calls this once per
    /// member, and re-hashing the bounded 1 MiB plan and checkpoint on every
    /// call would make maximum-body consensus application scale with proof
    /// count instead of body count.
    #[serde(skip_serializing)]
    body_commitment: [u8; 32],
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
        let body_commitment = admission_body_commitment(
            &proposal,
            &key,
            scope,
            &logical_owner,
            admission_fence,
            expected_generation,
        );
        Ok(Self {
            proposal,
            key,
            scope,
            logical_owner,
            admission_fence,
            expected_generation,
            body_commitment,
        })
    }
    pub(crate) const fn body_commitment(&self) -> [u8; 32] {
        self.body_commitment
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

fn admission_body_commitment(
    proposal: &AdmissionProposal,
    key: &SessionKey,
    scope: Scope,
    logical_owner: &OwnerId,
    admission_fence: FenceToken,
    expected_generation: Generation,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ADMISSION_DOMAIN);
    h.update(proposal.profile.digest());
    h.update(proposal.roster_id.as_bytes());
    update_len_prefixed(&mut h, &key.canonical_digest_input());
    h.update(scope.digest());
    update_len_prefixed(&mut h, logical_owner.as_str().as_bytes());
    h.update(admission_fence.get().to_be_bytes());
    h.update(expected_generation.get().to_be_bytes());
    h.update((proposal.members.len() as u64).to_be_bytes());
    for member in &proposal.members {
        h.update([member.ordinal]);
        h.update(member.operation_id.as_bytes());
        h.update(member.descriptor_commitment());
        h.update(member.expected_version.to_be_bytes());
    }
    h.update([proposal.established_mutation.tag()]);
    match proposal.established_mutation.state_type() {
        Some(state_type) => {
            h.update([1]);
            update_len_prefixed(&mut h, state_type.as_str().as_bytes());
        }
        None => h.update([0]),
    }
    update_len_prefixed(&mut h, &proposal.protected_plan);
    update_len_prefixed(&mut h, &proposal.terminal_checkpoint);
    update_len_prefixed(&mut h, &proposal.terminal_result);
    h.finalize().into()
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

    pub(crate) const fn history_epoch(self) -> u64 {
        self.history_epoch
    }

    /// Return the fixed-width canonical SQLite/index key without exposing a
    /// tenant, session key, or roster descriptor.
    pub(crate) fn to_bytes(self) -> [u8; 120] {
        let mut bytes = [0; 120];
        bytes[..8].copy_from_slice(&self.history_epoch.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.scope.digest());
        bytes[40..72].copy_from_slice(&self.tenant_scope_partition);
        bytes[72..104].copy_from_slice(&self.session_key_commitment);
        bytes[104..].copy_from_slice(self.roster_id.as_bytes());
        bytes
    }

    /// Decode the exact fixed-width SQLite/index key and revalidate every
    /// embedded domain value. This is not a lookup constructor: callers must
    /// still compare the decoded binding with its authenticated row body.
    pub(crate) fn from_bytes(bytes: [u8; 120]) -> Result<Self, Error> {
        let history_epoch =
            u64::from_be_bytes(bytes[..8].try_into().map_err(|_| Error::InvalidHistory)?);
        let scope = Scope::from_digest(bytes[8..40].try_into().map_err(|_| Error::InvalidHistory)?);
        let tenant_scope_partition = bytes[40..72]
            .try_into()
            .map_err(|_| Error::InvalidHistory)?;
        let session_key_commitment = bytes[72..104]
            .try_into()
            .map_err(|_| Error::InvalidHistory)?;
        let roster_id = RosterId::from_bytes(
            bytes[104..]
                .try_into()
                .map_err(|_| Error::InvalidRosterId)?,
        )?;
        let value = Self {
            history_epoch,
            scope,
            tenant_scope_partition,
            session_key_commitment,
            roster_id,
        };
        value.validate()?;
        if value.to_bytes() != bytes {
            return Err(Error::InvalidHistory);
        }
        Ok(value)
    }

    /// Return the stable scope-and-tenant partition key used for floor rows.
    pub(crate) fn partition_bytes(self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.scope.digest());
        bytes[32..].copy_from_slice(&self.tenant_scope_partition);
        bytes
    }

    /// Return the opaque exact-session commitment used for key reservations.
    pub(crate) const fn session_key_commitment(self) -> [u8; 32] {
        self.session_key_commitment
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

/// Compute the exact domain-separated session-key commitment used by durable
/// protected-roster bindings and their SQLite business reservation projection.
///
/// This is an internal persistence identity. Callers must use this helper
/// rather than independently recreating its framing or digest domain.
pub(crate) fn session_key_commitment(key: &SessionKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_KEY_BINDING_DOMAIN);
    update_len_prefixed(&mut hasher, &key.canonical_digest_input());
    hasher.finalize().into()
}

/// Compute the exact authenticated tenant/scope partition committed by a
/// durable protected-roster binding.
///
/// SQLite authorization and compact-evidence validation share this internal
/// helper so neither persistence path can silently drift from the immutable
/// request identity.
pub(crate) fn tenant_scope_partition_commitment(scope: Scope, key: &SessionKey) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TENANT_SCOPE_PARTITION_DOMAIN);
    hasher.update(scope.digest());
    update_len_prefixed(&mut hasher, key.tenant.as_str().as_bytes());
    hasher.finalize().into()
}

fn request_binding_key(
    history_epoch: u64,
    scope: Scope,
    key: &SessionKey,
    roster_id: RosterId,
) -> Result<RequestBindingKey, Error> {
    validate_history_epoch(history_epoch)?;
    scope.validate()?;
    let binding = RequestBindingKey {
        history_epoch,
        scope,
        tenant_scope_partition: tenant_scope_partition_commitment(scope, key),
        session_key_commitment: session_key_commitment(key),
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
/// use opc_session_store::fenced_mutation_roster::TerminalRecord;
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
    #[cfg(test)]
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
    pub(crate) fn from_canonical_bytes(bytes: &[u8], admission: &Admission) -> Result<Self, Error> {
        let value: Self = decode_frame(
            bytes,
            TERMINAL_FRAME_MAGIC,
            TERMINAL_FRAME_DOMAIN,
            MAX_TERMINAL_CODEC_BYTES,
        )?;
        value.validate_for(admission)?;
        if value.to_canonical_bytes(admission)? != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(value)
    }

    /// Validate a reclaimed terminal command's canonical self-commitment.
    ///
    /// Payload compaction deliberately removes the immutable admission, so a
    /// tombstone cannot call [`Self::from_canonical_bytes`]. This narrower
    /// witness still authenticates every terminal field against the embedded
    /// body commitment and requires a byte-exact canonical re-encoding. It
    /// does not authorize terminalization by itself; the state machine must
    /// separately authenticate the retained binding, current lease, original
    /// provenance, registration parts, and tombstone commitment.
    pub(crate) fn canonical_body_commitment(bytes: &[u8]) -> Result<[u8; 32], Error> {
        let value: Self = decode_frame(
            bytes,
            TERMINAL_FRAME_MAGIC,
            TERMINAL_FRAME_DOMAIN,
            MAX_TERMINAL_CODEC_BYTES,
        )?;
        value.validate_self_contained()?;
        if encode_frame(
            TERMINAL_FRAME_MAGIC,
            TERMINAL_FRAME_DOMAIN,
            &value,
            MAX_TERMINAL_CODEC_BYTES,
        )? != bytes
        {
            return Err(Error::InvalidTerminal);
        }
        Ok(value.body_commitment)
    }

    /// Validate the commitment-bound fields available without an admission.
    ///
    /// This is deliberately not an authorization check. It lets a retained
    /// committed-terminal capsule prove that its embedded terminal body is
    /// the exact canonical body named by the originating consensus command;
    /// full recovery still validates the body against the immutable admission.
    pub(crate) fn validate_self_contained(&self) -> Result<(), Error> {
        Scope::from_digest(self.scope).validate()?;
        if self.proof_commitments.is_empty()
            || self.proof_commitments.len() > MAX_MEMBERS
            || self.proof_commitments.contains(&[0; 32])
            || self.body_commitment == [0; 32]
            || self.body_commitment != self.calculate_body_commitment()
            || Phase::from_tag(self.phase_tag).is_err()
        {
            return Err(Error::InvalidTerminal);
        }
        Ok(())
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

/// Certificate role carried by the shared roster-attestation format.
///
/// The wire tag is deliberately shared with transport ingress so that an
/// ingress worker and an executor never invent subtly incompatible root
/// certificate encodings.  A roster terminal accepts only [`Self::Executor`].
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RosterAttestationCertificateRoleV1 {
    /// A leaf authorized to attest local provider execution observations.
    Executor,
    /// A leaf controlled by the product provider that performed the member
    /// operation. Provider receipts are independently required at Q2.
    Provider,
    /// A leaf reserved for authenticated transport-ingress assertions.
    TransportIngress,
}

impl RosterAttestationCertificateRoleV1 {
    #[doc(hidden)]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Executor => 1,
            Self::Provider => 2,
            Self::TransportIngress => 3,
        }
    }

    #[doc(hidden)]
    pub fn from_tag(tag: u8) -> Result<Self, RosterAttestationError> {
        match tag {
            1 => Ok(Self::Executor),
            2 => Ok(Self::Provider),
            3 => Ok(Self::TransportIngress),
            _ => Err(RosterAttestationError),
        }
    }
}

/// Fixed redacted error for attestation decoding, issuance, and verification.
///
/// It intentionally carries no cryptographic parser, key, certificate, or
/// provider evidence detail into consensus diagnostics.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RosterAttestationError;

impl fmt::Debug for RosterAttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterAttestationError(<redacted>)")
    }
}

impl fmt::Display for RosterAttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("roster attestation rejected")
    }
}

impl std::error::Error for RosterAttestationError {}

/// Immutable topology-provisioned P-256 root for roster attestations.
///
/// This value is configuration, not command data.  A terminal command never
/// chooses its verifier root; storage receives the root from the validated
/// topology that opened the consensus state machine.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RosterAttestationTrustRootV1 {
    root_id: [u8; 32],
    #[serde(with = "fixed_array_33")]
    public_key: [u8; ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES],
}

/// Opaque equality identity for one topology-provisioned roster trust root.
///
/// The listener can compare this value during startup without receiving a raw
/// public key, root identifier, serialization seam, or administrative signing
/// capability. Diagnostics remain fixed and redacted.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RosterAttestationTrustRootIdentityV1([u8; 32]);

impl fmt::Debug for RosterAttestationTrustRootIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterAttestationTrustRootIdentityV1(<redacted>)")
    }
}

impl RosterAttestationTrustRootV1 {
    /// Validate and provision one fixed P-256/SHA-256 roster trust root.
    pub fn new(
        root_id: [u8; 32],
        public_key: [u8; ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES],
    ) -> Result<Self, RosterAttestationError> {
        if root_id == [0; 32] || canonical_verifying_key(&public_key).is_err() {
            return Err(RosterAttestationError);
        }
        Ok(Self {
            root_id,
            public_key,
        })
    }

    /// Domain-separated immutable root/configuration fingerprint.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ROSTER_ATTESTATION_ROOT_DOMAIN);
        hasher.update([1]);
        hasher.update(self.root_id);
        hasher.update(self.public_key);
        hasher.finalize().into()
    }

    /// Return an opaque identity suitable only for local configuration
    /// equality checks.
    #[doc(hidden)]
    pub fn identity(&self) -> RosterAttestationTrustRootIdentityV1 {
        RosterAttestationTrustRootIdentityV1(self.fingerprint())
    }

    /// Return the fixed root identifier for configuration derivation only.
    #[doc(hidden)]
    pub const fn root_id(&self) -> [u8; 32] {
        self.root_id
    }

    /// Return the compressed SEC1 key for a local privileged signer/verifier.
    #[doc(hidden)]
    pub const fn compressed_public_key(
        &self,
    ) -> [u8; ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES] {
        self.public_key
    }
}

impl fmt::Debug for RosterAttestationTrustRootV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterAttestationTrustRootV1(<redacted>)")
    }
}

#[derive(Deserialize)]
struct RosterAttestationTrustRootWireV1 {
    root_id: [u8; 32],
    #[serde(with = "fixed_array_33")]
    public_key: [u8; ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES],
}

impl<'de> Deserialize<'de> for RosterAttestationTrustRootV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RosterAttestationTrustRootWireV1::deserialize(deserializer)?;
        Self::new(wire.root_id, wire.public_key).map_err(serde::de::Error::custom)
    }
}

/// Signed certificate components accepted only by the hidden SDK issuance
/// path.  This is deliberately not a typed certificate constructor: the
/// bundle builder verifies the root signature before it returns a typed value.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct RosterAttestationLeafCertificatePartsV1 {
    /// Topology-provisioned root id, never selected by a terminal command.
    pub root_id: [u8; 32],
    /// Shared leaf role tag.
    pub role: RosterAttestationCertificateRoleV1,
    /// Exact cluster/configuration/epoch scope.
    pub configuration_identity: SessionConsensusIdentity,
    /// Exact protected-roster authority scope digest.
    pub scope: [u8; 32],
    /// Stable opaque executor/ingress subject commitment.
    pub subject_identity_commitment: [u8; 32],
    /// Nonzero leaf certificate epoch.
    pub leaf_epoch: u64,
    /// Nonzero fixed-width rotated leaf key id.
    pub key_id: [u8; 32],
    /// Replicated-time validity lower bound.
    pub not_before: Timestamp,
    /// Replicated-time validity exclusive upper bound.
    pub not_after: Timestamp,
    /// Fixed compressed SEC1 P-256 leaf key.
    pub public_key: [u8; ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES],
    /// Fixed low-S P-256 `r || s` root signature.
    pub root_signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
}

/// One signed provider-proof component accepted by the hidden SDK issuance
/// path.  Its raw evidence remains bounded and is never retained after a
/// successful terminal transaction.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct RosterExecutorMemberProofPartsV1 {
    /// Ordered roster position.
    pub ordinal: u8,
    /// Local provider operation that established this observation.
    pub provider_operation: RosterProviderOperationV1,
    /// Conclusive provider outcome.
    pub outcome: RosterProviderOutcomeV1,
    /// Nonzero local proof epoch.
    pub proof_epoch: u64,
    /// Opaque nonempty provider evidence, bounded to 4096 bytes.
    pub evidence: Vec<u8>,
    /// Root-signed Provider leaf certificate for this exact member receipt.
    pub provider_certificate: RosterAttestationLeafCertificatePartsV1,
    /// Fixed low-S P-256 `r || s` Provider receipt signature.
    pub provider_signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
    /// Fixed low-S P-256 `r || s` leaf signature.
    pub signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
}

/// Fixed canonical operation tag used in a signed terminal proof.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RosterProviderOperationV1 {
    Execute,
    Status,
    Adopt,
    Compensate,
    Prepare,
    Reconcile,
}

impl RosterProviderOperationV1 {
    #[doc(hidden)]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Execute => PROVIDER_OPERATION_EXECUTE_TAG,
            Self::Status => PROVIDER_OPERATION_STATUS_TAG,
            Self::Adopt => PROVIDER_OPERATION_ADOPT_TAG,
            Self::Compensate => PROVIDER_OPERATION_COMPENSATE_TAG,
            Self::Prepare => PROVIDER_OPERATION_PREPARE_TAG,
            Self::Reconcile => PROVIDER_OPERATION_RECONCILE_TAG,
        }
    }

    #[doc(hidden)]
    pub fn from_tag(tag: u8) -> Result<Self, RosterAttestationError> {
        match tag {
            PROVIDER_OPERATION_EXECUTE_TAG => Ok(Self::Execute),
            PROVIDER_OPERATION_STATUS_TAG => Ok(Self::Status),
            PROVIDER_OPERATION_ADOPT_TAG => Ok(Self::Adopt),
            PROVIDER_OPERATION_COMPENSATE_TAG => Ok(Self::Compensate),
            PROVIDER_OPERATION_PREPARE_TAG => Ok(Self::Prepare),
            PROVIDER_OPERATION_RECONCILE_TAG => Ok(Self::Reconcile),
            _ => Err(RosterAttestationError),
        }
    }
}

/// Fixed canonical conclusive-outcome tag used in a signed terminal proof.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RosterProviderOutcomeV1 {
    AppliedExecuted,
    AppliedAdopted,
    NotAppliedReconciled,
    CompensatedReconciled,
}

impl RosterProviderOutcomeV1 {
    #[doc(hidden)]
    pub const fn tag(self) -> u8 {
        match self {
            Self::AppliedExecuted => OUTCOME_APPLIED_EXECUTED,
            Self::AppliedAdopted => OUTCOME_APPLIED_ADOPTED,
            Self::NotAppliedReconciled => OUTCOME_NOT_APPLIED_RECONCILED,
            Self::CompensatedReconciled => OUTCOME_COMPENSATED_RECONCILED,
        }
    }

    #[doc(hidden)]
    pub fn from_tag(tag: u8) -> Result<Self, RosterAttestationError> {
        match tag {
            OUTCOME_APPLIED_EXECUTED => Ok(Self::AppliedExecuted),
            OUTCOME_APPLIED_ADOPTED => Ok(Self::AppliedAdopted),
            OUTCOME_NOT_APPLIED_RECONCILED => Ok(Self::NotAppliedReconciled),
            OUTCOME_COMPENSATED_RECONCILED => Ok(Self::CompensatedReconciled),
            _ => Err(RosterAttestationError),
        }
    }

    const fn phase(self) -> Phase {
        match self {
            Self::AppliedExecuted | Self::AppliedAdopted => Phase::Established,
            Self::NotAppliedReconciled | Self::CompensatedReconciled => Phase::Aborted,
        }
    }
}

#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RosterAttestationLeafCertificateV1 {
    root_id: [u8; 32],
    role_tag: u8,
    configuration_identity: SessionConsensusIdentity,
    scope: [u8; 32],
    subject_identity_commitment: [u8; 32],
    leaf_epoch: u64,
    key_id: [u8; 32],
    not_before: Timestamp,
    not_after: Timestamp,
    #[serde(with = "fixed_array_33")]
    public_key: [u8; ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES],
    #[serde(with = "fixed_array_64")]
    root_signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
}

impl RosterAttestationLeafCertificateV1 {
    /// Compute the root-signature digest from every non-signature certificate
    /// field. This is intentionally available before a root signature exists.
    #[doc(hidden)]
    pub fn signing_digest(
        parts: &RosterAttestationLeafCertificatePartsV1,
    ) -> Result<[u8; 32], RosterAttestationError> {
        Ok(Self::from_unsigned_parts(parts)?.root_signing_digest())
    }

    /// Validate a root-signed generic leaf certificate.  The returned
    /// certificate keeps all wire fields private, so an SDK caller cannot
    /// manufacture a validated typed certificate by struct literal.
    #[doc(hidden)]
    pub fn issue_from_signed_parts(
        root: &RosterAttestationTrustRootV1,
        parts: RosterAttestationLeafCertificatePartsV1,
    ) -> Result<Self, RosterAttestationError> {
        let value = Self::from_parts(parts)?;
        value.verify_root(root)?;
        Ok(value)
    }

    /// Verify this generic certificate against one topology-provisioned root.
    #[doc(hidden)]
    pub fn verify_against_root(
        &self,
        root: &RosterAttestationTrustRootV1,
    ) -> Result<(), RosterAttestationError> {
        self.verify_root(root)
    }

    /// Return the bound certificate role without exposing opaque certificate
    /// contents.
    #[doc(hidden)]
    pub fn role(&self) -> Result<RosterAttestationCertificateRoleV1, RosterAttestationError> {
        RosterAttestationCertificateRoleV1::from_tag(self.role_tag)
    }

    fn from_unsigned_parts(
        parts: &RosterAttestationLeafCertificatePartsV1,
    ) -> Result<Self, RosterAttestationError> {
        let value = Self {
            root_id: parts.root_id,
            role_tag: parts.role.tag(),
            configuration_identity: parts.configuration_identity,
            scope: parts.scope,
            subject_identity_commitment: parts.subject_identity_commitment,
            leaf_epoch: parts.leaf_epoch,
            key_id: parts.key_id,
            not_before: parts.not_before,
            not_after: parts.not_after,
            public_key: parts.public_key,
            // Root signature is intentionally not considered by unsigned
            // validation.  This is the only way a root signer can obtain the
            // exact certificate preimage before a signature exists.
            root_signature: [0; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
        };
        value.validate_unsigned_structure()?;
        Ok(value)
    }

    fn from_parts(
        parts: RosterAttestationLeafCertificatePartsV1,
    ) -> Result<Self, RosterAttestationError> {
        let value = Self {
            root_id: parts.root_id,
            role_tag: parts.role.tag(),
            configuration_identity: parts.configuration_identity,
            scope: parts.scope,
            subject_identity_commitment: parts.subject_identity_commitment,
            leaf_epoch: parts.leaf_epoch,
            key_id: parts.key_id,
            not_before: parts.not_before,
            not_after: parts.not_after,
            public_key: parts.public_key,
            root_signature: parts.root_signature,
        };
        value.validate_structure()?;
        Ok(value)
    }

    fn validate_unsigned_structure(&self) -> Result<(), RosterAttestationError> {
        if self.root_id == [0; 32]
            || self.scope == [0; 32]
            || self.subject_identity_commitment == [0; 32]
            || self.leaf_epoch == 0
            || self.key_id == [0; 32]
            || self.not_after <= self.not_before
            || RosterAttestationCertificateRoleV1::from_tag(self.role_tag).is_err()
            || canonical_verifying_key(&self.public_key).is_err()
        {
            return Err(RosterAttestationError);
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), RosterAttestationError> {
        self.validate_unsigned_structure()?;
        if canonical_signature(&self.root_signature).is_err() {
            return Err(RosterAttestationError);
        }
        Ok(())
    }

    fn root_signing_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(ROSTER_ATTESTATION_CERTIFICATE_DOMAIN);
        hasher.update([1]);
        hasher.update(self.root_id);
        hasher.update([self.role_tag]);
        update_consensus_identity_attestation(&mut hasher, self.configuration_identity);
        hasher.update(self.scope);
        hasher.update(self.subject_identity_commitment);
        hasher.update(self.leaf_epoch.to_be_bytes());
        hasher.update(self.key_id);
        update_timestamp_attestation(&mut hasher, self.not_before);
        update_timestamp_attestation(&mut hasher, self.not_after);
        hasher.update(self.public_key);
        hasher.finalize().into()
    }

    fn verify_root(
        &self,
        root: &RosterAttestationTrustRootV1,
    ) -> Result<(), RosterAttestationError> {
        self.validate_structure()?;
        if self.root_id != root.root_id {
            return Err(RosterAttestationError);
        }
        verify_digest_signature(
            &root.public_key,
            self.root_signing_digest(),
            &self.root_signature,
        )
    }
}

impl<'de> Deserialize<'de> for RosterAttestationLeafCertificateV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            root_id: [u8; 32],
            role_tag: u8,
            configuration_identity: SessionConsensusIdentity,
            scope: [u8; 32],
            subject_identity_commitment: [u8; 32],
            leaf_epoch: u64,
            key_id: [u8; 32],
            not_before: Timestamp,
            not_after: Timestamp,
            #[serde(with = "fixed_array_33")]
            public_key: [u8; ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES],
            #[serde(with = "fixed_array_64")]
            root_signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            root_id: wire.root_id,
            role_tag: wire.role_tag,
            configuration_identity: wire.configuration_identity,
            scope: wire.scope,
            subject_identity_commitment: wire.subject_identity_commitment,
            leaf_epoch: wire.leaf_epoch,
            key_id: wire.key_id,
            not_before: wire.not_before,
            not_after: wire.not_after,
            public_key: wire.public_key,
            root_signature: wire.root_signature,
        };
        value
            .validate_structure()
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct RosterExecutorMemberProofV1 {
    ordinal: u8,
    operation_tag: u8,
    outcome_tag: u8,
    proof_epoch: u64,
    evidence: Vec<u8>,
    provider_certificate: RosterAttestationLeafCertificateV1,
    #[serde(with = "fixed_array_64")]
    provider_signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
    #[serde(with = "fixed_array_64")]
    signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
}

impl RosterExecutorMemberProofV1 {
    fn from_parts(parts: RosterExecutorMemberProofPartsV1) -> Result<Self, RosterAttestationError> {
        let value = Self {
            ordinal: parts.ordinal,
            operation_tag: parts.provider_operation.tag(),
            outcome_tag: parts.outcome.tag(),
            proof_epoch: parts.proof_epoch,
            evidence: parts.evidence,
            provider_certificate: RosterAttestationLeafCertificateV1::from_parts(
                parts.provider_certificate,
            )?,
            provider_signature: parts.provider_signature,
            signature: parts.signature,
        };
        value.validate_structure()?;
        Ok(value)
    }

    fn validate_structure(&self) -> Result<(), RosterAttestationError> {
        if self.ordinal as usize >= MAX_MEMBERS
            || self.proof_epoch == 0
            || self.evidence.is_empty()
            || self.evidence.len() > MAX_EXECUTOR_PROOF_EVIDENCE_BYTES
            || RosterProviderOperationV1::from_tag(self.operation_tag).is_err()
            || RosterProviderOutcomeV1::from_tag(self.outcome_tag).is_err()
            || self.provider_certificate.validate_structure().is_err()
            || self.provider_certificate.role()? != RosterAttestationCertificateRoleV1::Provider
            || canonical_signature(&self.provider_signature).is_err()
            || canonical_signature(&self.signature).is_err()
        {
            return Err(RosterAttestationError);
        }
        Ok(())
    }

    fn operation(&self) -> Result<RosterProviderOperationV1, RosterAttestationError> {
        RosterProviderOperationV1::from_tag(self.operation_tag)
    }

    fn outcome(&self) -> Result<RosterProviderOutcomeV1, RosterAttestationError> {
        RosterProviderOutcomeV1::from_tag(self.outcome_tag)
    }

    fn evidence_commitment(&self) -> [u8; 32] {
        evidence_commitment_from_bytes(&self.evidence)
    }
}

impl<'de> Deserialize<'de> for RosterExecutorMemberProofV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            ordinal: u8,
            operation_tag: u8,
            outcome_tag: u8,
            proof_epoch: u64,
            evidence: BoundedBytes<MAX_EXECUTOR_PROOF_EVIDENCE_BYTES>,
            provider_certificate: RosterAttestationLeafCertificateV1,
            #[serde(with = "fixed_array_64")]
            provider_signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
            #[serde(with = "fixed_array_64")]
            signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            ordinal: wire.ordinal,
            operation_tag: wire.operation_tag,
            outcome_tag: wire.outcome_tag,
            proof_epoch: wire.proof_epoch,
            evidence: wire.evidence.0,
            provider_certificate: wire.provider_certificate,
            provider_signature: wire.provider_signature,
            signature: wire.signature,
        };
        value
            .validate_structure()
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Canonically bounded root-certified executor proof bundle.
///
/// All fields are private. The only issuance path verifies the supplied root
/// certificate and structural canonicality before a typed bundle is returned;
/// final command-specific verification happens deterministically in apply.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RosterExecutorProofBundleV1 {
    certificate: RosterAttestationLeafCertificateV1,
    proofs: Vec<RosterExecutorMemberProofV1>,
}

impl RosterExecutorProofBundleV1 {
    /// Issue a typed bundle from already-signed privileged components.
    ///
    /// Possession of these components alone cannot authorize a terminal: this
    /// verifies only the topology root certificate. Apply later reconstructs
    /// every command-specific proof preimage and verifies each leaf signature.
    #[doc(hidden)]
    pub fn issue_from_signed_parts(
        root: &RosterAttestationTrustRootV1,
        certificate: RosterAttestationLeafCertificatePartsV1,
        proofs: Vec<RosterExecutorMemberProofPartsV1>,
    ) -> Result<Self, RosterAttestationError> {
        let certificate = RosterAttestationLeafCertificateV1::from_parts(certificate)?;
        certificate.verify_root(root)?;
        let proofs = proofs
            .into_iter()
            .map(|parts| {
                let proof = RosterExecutorMemberProofV1::from_parts(parts)?;
                proof.provider_certificate.verify_root(root)?;
                Ok(proof)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let value = Self {
            certificate,
            proofs,
        };
        value.validate_structure()?;
        let bytes = value.canonical_bytes()?;
        if bytes.len() > MAX_EXECUTOR_PROOF_BUNDLE_BYTES {
            return Err(RosterAttestationError);
        }
        Ok(value)
    }

    /// Decode only the exact canonical bounded wire form.  This is provided
    /// for SDK ingress/signing crates; it does not choose or trust a root.
    #[doc(hidden)]
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RosterAttestationError> {
        if bytes.is_empty() || bytes.len() > MAX_EXECUTOR_PROOF_BUNDLE_BYTES {
            return Err(RosterAttestationError);
        }
        let value: Self = postcard::from_bytes(bytes).map_err(|_| RosterAttestationError)?;
        value.validate_structure()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RosterAttestationError);
        }
        Ok(value)
    }

    /// Return exact bounded canonical bytes for the private consensus envelope.
    #[doc(hidden)]
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RosterAttestationError> {
        self.validate_structure()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| RosterAttestationError)?;
        if bytes.len() > MAX_EXECUTOR_PROOF_BUNDLE_BYTES {
            return Err(RosterAttestationError);
        }
        Ok(bytes)
    }

    fn validate_structure(&self) -> Result<(), RosterAttestationError> {
        self.certificate.validate_structure()?;
        if self.proofs.is_empty() || self.proofs.len() > MAX_MEMBERS {
            return Err(RosterAttestationError);
        }
        let mut previous = None;
        for proof in &self.proofs {
            proof.validate_structure()?;
            if previous.is_some_and(|ordinal| proof.ordinal <= ordinal) {
                return Err(RosterAttestationError);
            }
            previous = Some(proof.ordinal);
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn certificate_signing_digest(
        parts: &RosterAttestationLeafCertificatePartsV1,
    ) -> Result<[u8; 32], RosterAttestationError> {
        RosterAttestationLeafCertificateV1::signing_digest(parts)
    }
}

impl fmt::Debug for RosterExecutorProofBundleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterExecutorProofBundleV1(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for RosterExecutorProofBundleV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            certificate: RosterAttestationLeafCertificateV1,
            proofs: BoundedVec<RosterExecutorMemberProofV1, MAX_MEMBERS>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            certificate: wire.certificate,
            proofs: wire.proofs.0,
        };
        value
            .validate_structure()
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Exact, redaction-safe leaf-signature preimage for one terminal member.
///
/// This hidden public input is intentionally data-only: a caller can ask its
/// privileged local signer to sign a digest, but cannot turn that digest into
/// an accepted terminal unless SQLite reconstructs byte-identical values from
/// the retained admission, registration, current authority, and terminal.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct RosterTerminalAttestationSigningInputV1 {
    pub profile: Profile,
    pub configuration_identity: SessionConsensusIdentity,
    pub certificate_subject_identity_commitment: [u8; 32],
    pub certificate_role: RosterAttestationCertificateRoleV1,
    pub binding: [u8; 120],
    pub registration_handle: [u8; 32],
    pub registration_request_id: [u8; 56],
    pub registration_terminal_slot: [u8; 32],
    pub roster_id: [u8; ROSTER_ID_BYTES],
    pub admission_commitment: [u8; 32],
    pub terminal_phase: Phase,
    pub terminal_body_commitment: [u8; 32],
    pub ordinal: u8,
    pub member_operation_id: [u8; MEMBER_OPERATION_ID_BYTES],
    pub descriptor: Vec<u8>,
    pub descriptor_commitment: [u8; 32],
    pub expected_member_version: u64,
    pub admission_generation: u64,
    pub authority_scope: [u8; 32],
    pub authority_key_canonical: Vec<u8>,
    pub authority_owner: Vec<u8>,
    pub authority_fence: u64,
    pub authority_credential_id: u64,
    pub authority_generation: u64,
    pub authority_acquired_at: Timestamp,
    pub authority_expires_at: Timestamp,
    pub proof_epoch: u64,
    pub provider_operation: RosterProviderOperationV1,
    pub outcome: RosterProviderOutcomeV1,
    pub evidence: Vec<u8>,
}

impl RosterTerminalAttestationSigningInputV1 {
    /// Validate bounded canonical field values and return the exact P-256
    /// prehash signed by an Executor leaf.
    #[doc(hidden)]
    pub fn digest(&self) -> Result<[u8; 32], RosterAttestationError> {
        if self.profile.validate().is_err()
            || self.certificate_subject_identity_commitment == [0; 32]
            || self.registration_handle == [0; 32]
            || self.registration_terminal_slot == [0; 32]
            || self.admission_commitment == [0; 32]
            || self.terminal_body_commitment == [0; 32]
            || self.member_operation_id == [0; MEMBER_OPERATION_ID_BYTES]
            || self.descriptor.is_empty()
            || self.descriptor.len() > MAX_DESCRIPTOR_BYTES
            || self.expected_member_version == 0
            || self.admission_generation == 0
            || self.authority_scope == [0; 32]
            || self.authority_key_canonical.is_empty()
            || self.authority_owner.is_empty()
            || self.authority_fence == 0
            || self.authority_credential_id == 0
            || self.authority_generation == 0
            || self.authority_expires_at <= self.authority_acquired_at
            || self.proof_epoch == 0
            || self.evidence.is_empty()
            || self.evidence.len() > MAX_EXECUTOR_PROOF_EVIDENCE_BYTES
        {
            return Err(RosterAttestationError);
        }
        let descriptor_commitment = descriptor_commitment_from_bytes(&self.descriptor);
        if descriptor_commitment != self.descriptor_commitment {
            return Err(RosterAttestationError);
        }
        let evidence_commitment = evidence_commitment_from_bytes(&self.evidence);
        let mut hasher = Sha256::new();
        hasher.update(ROSTER_ATTESTATION_PROOF_DOMAIN);
        hasher.update([1]);
        hasher.update(self.profile.schema().to_be_bytes());
        hasher.update(self.profile.consumer_revision().to_be_bytes());
        hasher.update(self.profile.digest());
        update_consensus_identity_attestation(&mut hasher, self.configuration_identity);
        hasher.update(self.certificate_subject_identity_commitment);
        hasher.update([self.certificate_role.tag()]);
        hasher.update(self.binding);
        hasher.update(self.registration_handle);
        hasher.update(self.registration_request_id);
        hasher.update(self.registration_terminal_slot);
        hasher.update(self.roster_id);
        hasher.update(self.admission_commitment);
        hasher.update([self.terminal_phase.tag()]);
        hasher.update(self.terminal_body_commitment);
        hasher.update([self.ordinal]);
        hasher.update(self.member_operation_id);
        hasher.update((self.descriptor.len() as u64).to_be_bytes());
        hasher.update(&self.descriptor);
        hasher.update(self.descriptor_commitment);
        hasher.update(self.expected_member_version.to_be_bytes());
        hasher.update(self.admission_generation.to_be_bytes());
        hasher.update(self.authority_scope);
        update_len_prefixed(&mut hasher, &self.authority_key_canonical);
        update_len_prefixed(&mut hasher, &self.authority_owner);
        hasher.update(self.authority_fence.to_be_bytes());
        hasher.update(self.authority_credential_id.to_be_bytes());
        hasher.update(self.authority_generation.to_be_bytes());
        update_timestamp_attestation(&mut hasher, self.authority_acquired_at);
        update_timestamp_attestation(&mut hasher, self.authority_expires_at);
        hasher.update(self.proof_epoch.to_be_bytes());
        hasher.update([self.provider_operation.tag(), self.outcome.tag()]);
        hasher.update((self.evidence.len() as u64).to_be_bytes());
        hasher.update(&self.evidence);
        hasher.update(evidence_commitment);
        Ok(hasher.finalize().into())
    }
}

/// Exact, redaction-safe Provider leaf-signature preimage for a single
/// conclusive member receipt.
///
/// This is intentionally separate from [`RosterTerminalAttestationSigningInputV1`]:
/// a receipt is minted before Q2 and therefore commits neither an
/// Established/Aborted choice nor a terminal record body. It does bind the
/// complete frozen admission/current-authority tuple that makes a provider
/// assertion meaningful to deterministic consensus.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct RosterProviderReceiptSigningInputV1 {
    pub profile: Profile,
    pub configuration_identity: SessionConsensusIdentity,
    pub certificate_subject_identity_commitment: [u8; 32],
    pub certificate_role: RosterAttestationCertificateRoleV1,
    pub binding: [u8; 120],
    pub registration_handle: [u8; 32],
    pub registration_request_id: [u8; 56],
    pub registration_terminal_slot: [u8; 32],
    pub roster_id: [u8; ROSTER_ID_BYTES],
    pub admission_commitment: [u8; 32],
    pub ordinal: u8,
    pub member_operation_id: [u8; MEMBER_OPERATION_ID_BYTES],
    pub descriptor: Vec<u8>,
    pub descriptor_commitment: [u8; 32],
    pub expected_member_version: u64,
    pub admission_generation: u64,
    pub authority_scope: [u8; 32],
    pub authority_key_canonical: Vec<u8>,
    pub authority_owner: Vec<u8>,
    pub authority_fence: u64,
    pub authority_credential_id: u64,
    pub authority_generation: u64,
    pub authority_acquired_at: Timestamp,
    pub authority_expires_at: Timestamp,
    pub proof_epoch: u64,
    pub provider_operation: RosterProviderOperationV1,
    pub outcome: RosterProviderOutcomeV1,
    pub evidence: Vec<u8>,
}

impl RosterProviderReceiptSigningInputV1 {
    /// Derive the Provider receipt input from the same immutable/current
    /// member facts used for executor aggregation. The Provider identity is
    /// supplied separately so certificate roles cannot be confused.
    #[doc(hidden)]
    pub fn from_terminal_input(
        input: &RosterTerminalAttestationSigningInputV1,
        provider_subject_identity_commitment: [u8; 32],
    ) -> Result<Self, RosterAttestationError> {
        input.digest()?;
        Ok(Self {
            profile: input.profile,
            configuration_identity: input.configuration_identity,
            certificate_subject_identity_commitment: provider_subject_identity_commitment,
            certificate_role: RosterAttestationCertificateRoleV1::Provider,
            binding: input.binding,
            registration_handle: input.registration_handle,
            registration_request_id: input.registration_request_id,
            registration_terminal_slot: input.registration_terminal_slot,
            roster_id: input.roster_id,
            admission_commitment: input.admission_commitment,
            ordinal: input.ordinal,
            member_operation_id: input.member_operation_id,
            descriptor: input.descriptor.clone(),
            descriptor_commitment: input.descriptor_commitment,
            expected_member_version: input.expected_member_version,
            admission_generation: input.admission_generation,
            authority_scope: input.authority_scope,
            authority_key_canonical: input.authority_key_canonical.clone(),
            authority_owner: input.authority_owner.clone(),
            authority_fence: input.authority_fence,
            authority_credential_id: input.authority_credential_id,
            authority_generation: input.authority_generation,
            authority_acquired_at: input.authority_acquired_at,
            authority_expires_at: input.authority_expires_at,
            proof_epoch: input.proof_epoch,
            provider_operation: input.provider_operation,
            outcome: input.outcome,
            evidence: input.evidence.clone(),
        })
    }

    /// Return the exact Provider receipt digest. This domain deliberately has
    /// no terminal phase or terminal body fields.
    #[doc(hidden)]
    pub fn digest(&self) -> Result<[u8; 32], RosterAttestationError> {
        if self.profile.validate().is_err()
            || self.certificate_subject_identity_commitment == [0; 32]
            || self.certificate_role != RosterAttestationCertificateRoleV1::Provider
            || self.registration_handle == [0; 32]
            || self.registration_terminal_slot == [0; 32]
            || self.admission_commitment == [0; 32]
            || self.member_operation_id == [0; MEMBER_OPERATION_ID_BYTES]
            || self.descriptor.is_empty()
            || self.descriptor.len() > MAX_DESCRIPTOR_BYTES
            || self.expected_member_version == 0
            || self.admission_generation == 0
            || self.authority_scope == [0; 32]
            || self.authority_key_canonical.is_empty()
            || self.authority_owner.is_empty()
            || self.authority_fence == 0
            || self.authority_credential_id == 0
            || self.authority_generation == 0
            || self.authority_expires_at <= self.authority_acquired_at
            || self.proof_epoch == 0
            || self.evidence.is_empty()
            || self.evidence.len() > MAX_EXECUTOR_PROOF_EVIDENCE_BYTES
            || !attested_provider_outcome_allowed(self.provider_operation, self.outcome)
        {
            return Err(RosterAttestationError);
        }
        if RequestBindingKey::from_bytes(self.binding).is_err()
            || descriptor_commitment_from_bytes(&self.descriptor) != self.descriptor_commitment
        {
            return Err(RosterAttestationError);
        }
        provider_receipt_digest_from_challenge_v1(
            self.challenge_digest()?,
            self.certificate_subject_identity_commitment,
            self.proof_epoch,
            self.provider_operation,
            self.outcome,
            &self.evidence,
        )
    }

    /// Return the opaque fixed-call challenge used by the protected Provider
    /// host.  It deliberately excludes Provider identity and the conclusive
    /// outcome/evidence, while binding every immutable registration/member and
    /// current-authority fact reconstructed by consensus.
    #[doc(hidden)]
    pub fn challenge_digest(&self) -> Result<[u8; 32], RosterAttestationError> {
        if self.profile.validate().is_err()
            || self.registration_handle == [0; 32]
            || self.registration_terminal_slot == [0; 32]
            || self.admission_commitment == [0; 32]
            || self.member_operation_id == [0; MEMBER_OPERATION_ID_BYTES]
            || self.descriptor.is_empty()
            || self.descriptor.len() > MAX_DESCRIPTOR_BYTES
            || self.expected_member_version == 0
            || self.admission_generation == 0
            || self.authority_scope == [0; 32]
            || self.authority_key_canonical.is_empty()
            || self.authority_owner.is_empty()
            || self.authority_fence == 0
            || self.authority_credential_id == 0
            || self.authority_generation == 0
            || self.authority_expires_at <= self.authority_acquired_at
            || self.proof_epoch == 0
        {
            return Err(RosterAttestationError);
        }
        if RequestBindingKey::from_bytes(self.binding).is_err()
            || descriptor_commitment_from_bytes(&self.descriptor) != self.descriptor_commitment
        {
            return Err(RosterAttestationError);
        }
        let mut hasher = Sha256::new();
        hasher.update(ROSTER_ATTESTATION_PROVIDER_RECEIPT_DOMAIN);
        hasher.update(ROSTER_ATTESTATION_PROVIDER_RECEIPT_MAGIC);
        hasher.update([2]);
        hasher.update(self.profile.schema().to_be_bytes());
        hasher.update(self.profile.consumer_revision().to_be_bytes());
        hasher.update(self.profile.digest());
        update_consensus_identity_attestation(&mut hasher, self.configuration_identity);
        hasher.update(self.binding);
        hasher.update(self.registration_handle);
        hasher.update(self.registration_request_id);
        hasher.update(self.registration_terminal_slot);
        hasher.update(self.roster_id);
        hasher.update(self.admission_commitment);
        hasher.update([self.ordinal]);
        hasher.update(self.member_operation_id);
        hasher.update((self.descriptor.len() as u64).to_be_bytes());
        hasher.update(self.descriptor_commitment);
        hasher.update(self.expected_member_version.to_be_bytes());
        hasher.update(self.admission_generation.to_be_bytes());
        hasher.update(self.authority_scope);
        hasher.update(compact_session_key_commitment_from_canonical(
            &self.authority_key_canonical,
        ));
        hasher.update(compact_owner_commitment_from_canonical(
            &self.authority_owner,
        ));
        hasher.update(self.authority_fence.to_be_bytes());
        hasher.update(self.authority_credential_id.to_be_bytes());
        hasher.update(self.authority_generation.to_be_bytes());
        update_timestamp_attestation(&mut hasher, self.authority_acquired_at);
        update_timestamp_attestation(&mut hasher, self.authority_expires_at);
        hasher.update(self.proof_epoch.to_be_bytes());
        hasher.update([self.provider_operation.tag()]);
        Ok(hasher.finalize().into())
    }
}

/// Return the exact Provider-leaf digest for an opaque fixed-call challenge.
///
/// This is the only public signing preimage helper.  It cannot select the
/// immutable call binding; that binding was frozen by the SDK into `challenge`.
#[doc(hidden)]
pub fn provider_receipt_digest_from_challenge_v1(
    challenge: [u8; 32],
    provider_subject_identity_commitment: [u8; 32],
    proof_epoch: u64,
    operation: RosterProviderOperationV1,
    outcome: RosterProviderOutcomeV1,
    evidence: &[u8],
) -> Result<[u8; 32], RosterAttestationError> {
    if challenge == [0; 32]
        || provider_subject_identity_commitment == [0; 32]
        || proof_epoch == 0
        || evidence.is_empty()
        || evidence.len() > MAX_EXECUTOR_PROOF_EVIDENCE_BYTES
        || !attested_provider_outcome_allowed(operation, outcome)
    {
        return Err(RosterAttestationError);
    }
    provider_receipt_digest_from_challenge_commitment_v1(
        challenge,
        provider_subject_identity_commitment,
        proof_epoch,
        operation,
        outcome,
        evidence.len(),
        evidence_commitment_from_bytes(evidence),
    )
}

/// Shared final Provider-leaf digest over an exact fixed-call challenge and
/// an evidence commitment. Compact Q2 verification retains that same bounded
/// length/commitment pair but not raw evidence bytes, so it must use this
/// exact preimage rather than a second receipt domain.
fn provider_receipt_digest_from_challenge_commitment_v1(
    challenge: [u8; 32],
    provider_subject_identity_commitment: [u8; 32],
    proof_epoch: u64,
    operation: RosterProviderOperationV1,
    outcome: RosterProviderOutcomeV1,
    evidence_length: usize,
    evidence_commitment: [u8; 32],
) -> Result<[u8; 32], RosterAttestationError> {
    if challenge == [0; 32]
        || provider_subject_identity_commitment == [0; 32]
        || proof_epoch == 0
        || evidence_length == 0
        || evidence_length > MAX_EXECUTOR_PROOF_EVIDENCE_BYTES
        || evidence_commitment == [0; 32]
        || !attested_provider_outcome_allowed(operation, outcome)
    {
        return Err(RosterAttestationError);
    }
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_ATTESTATION_PROVIDER_RECEIPT_DOMAIN);
    hasher.update(ROSTER_ATTESTATION_PROVIDER_RECEIPT_MAGIC);
    hasher.update([3]);
    hasher.update(challenge);
    hasher.update(provider_subject_identity_commitment);
    hasher.update([RosterAttestationCertificateRoleV1::Provider.tag()]);
    hasher.update(proof_epoch.to_be_bytes());
    hasher.update([operation.tag(), outcome.tag()]);
    hasher.update((evidence_length as u64).to_be_bytes());
    hasher.update(evidence_commitment);
    Ok(hasher.finalize().into())
}

/// Verify one provider receipt before an executor promotes it into an
/// SDK-issued conclusive member proof.
///
/// Consensus independently repeats the same root, certificate, authority,
/// and signature checks when Q2 is applied.  This preflight helper exists so
/// an untrusted consumer cannot turn arbitrary caller-authored disposition
/// bytes into an [`Applied`](RosterProviderOutcomeV1::AppliedExecuted) proof
/// between Q1 and Q2.
#[doc(hidden)]
pub fn verify_roster_provider_receipt_v1(
    root: &RosterAttestationTrustRootV1,
    logical_time: Timestamp,
    certificate_parts: RosterAttestationLeafCertificatePartsV1,
    input: &RosterProviderReceiptSigningInputV1,
    signature: &[u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
) -> Result<(), RosterAttestationError> {
    let certificate =
        RosterAttestationLeafCertificateV1::issue_from_signed_parts(root, certificate_parts)?;
    if certificate.role()? != RosterAttestationCertificateRoleV1::Provider
        || certificate.configuration_identity != input.configuration_identity
        || certificate.scope != input.authority_scope
        || certificate.subject_identity_commitment != input.certificate_subject_identity_commitment
        || logical_time < certificate.not_before
        || logical_time >= certificate.not_after
        || logical_time < input.authority_acquired_at
        || logical_time >= input.authority_expires_at
    {
        return Err(RosterAttestationError);
    }
    verify_digest_signature(&certificate.public_key, input.digest()?, signature)
}

/// Commit one exact canonical opaque consumer capsule for a fixed roster
/// ingress operation. Both the ingress signer and deterministic consensus
/// apply use this helper, so no SDK crate reimplements the domain or length
/// framing.
#[doc(hidden)]
pub fn roster_ingress_capsule_commitment(
    operation_tag: u8,
    canonical_capsule: &[u8],
) -> Result<[u8; 32], RosterAttestationError> {
    if operation_tag == 0 || canonical_capsule.is_empty() {
        return Err(RosterAttestationError);
    }
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_INGRESS_CAPSULE_DOMAIN);
    hasher.update([operation_tag]);
    hasher.update((canonical_capsule.len() as u64).to_be_bytes());
    hasher.update(canonical_capsule);
    Ok(hasher.finalize().into())
}

/// Shared transport-ingress leaf-signature preimage. It deliberately uses the
/// same root-certified leaf format as Executor and fixes the /3 profile
/// binding, while leaving command carriage to the ingress/service layer.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterIngressAttestationSigningInputV1 {
    pub peer_identity_commitment: [u8; 32],
    pub consumer_scope: [u8; 32],
    pub request_id: [u8; 16],
    pub operation_tag: u8,
    pub canonical_capsule_digest: [u8; 32],
    pub authenticated_at: Timestamp,
    pub peer_certificate_expires_at: Timestamp,
    pub material_generation: u64,
    pub handshake_epoch: u64,
}

impl RosterIngressAttestationSigningInputV1 {
    /// Return the fixed transport-ingress leaf prehash. The caller must later
    /// verify it against a `TransportIngress` certificate and trusted root.
    #[doc(hidden)]
    pub fn digest(&self) -> Result<[u8; 32], RosterAttestationError> {
        if self.peer_identity_commitment == [0; 32]
            || self.consumer_scope == [0; 32]
            || self.request_id == [0; 16]
            || self.operation_tag == 0
            || self.canonical_capsule_digest == [0; 32]
            || self.peer_certificate_expires_at <= self.authenticated_at
            || self.material_generation == 0
            || self.handshake_epoch == 0
        {
            return Err(RosterAttestationError);
        }
        let mut hasher = Sha256::new();
        hasher.update(ROSTER_INGRESS_ATTESTATION_DOMAIN);
        hasher.update([1]);
        hasher.update(CONSUMER_ALPN);
        hasher.update(SCHEMA_V1.to_be_bytes());
        hasher.update(CONSUMER_REVISION.to_be_bytes());
        hasher.update(profile_digest());
        hasher.update(self.peer_identity_commitment);
        hasher.update(self.consumer_scope);
        hasher.update(self.request_id);
        hasher.update([self.operation_tag]);
        hasher.update(self.canonical_capsule_digest);
        update_timestamp_attestation(&mut hasher, self.authenticated_at);
        update_timestamp_attestation(&mut hasher, self.peer_certificate_expires_at);
        hasher.update(self.material_generation.to_be_bytes());
        hasher.update(self.handshake_epoch.to_be_bytes());
        Ok(hasher.finalize().into())
    }
}

/// Fixed root-certified transport-ingress statement. It never selects a root;
/// verification requires the independently topology-provisioned trust root.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RosterIngressAttestationV1 {
    certificate: RosterAttestationLeafCertificateV1,
    input: RosterIngressAttestationSigningInputV1,
    #[serde(with = "fixed_array_64")]
    signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
}

/// Exact connection values that an ingress attestation must bind.  Grouping
/// these inputs keeps verification call sites explicit without changing the
/// signed digest or its validation order.
#[doc(hidden)]
pub struct RosterIngressAttestationVerificationInputV1<'a> {
    pub configuration_identity: &'a SessionConsensusIdentity,
    pub expected_peer_identity_commitment: [u8; 32],
    pub expected_scope: [u8; 32],
    pub expected_request_id: [u8; 16],
    pub expected_operation_tag: u8,
    pub expected_capsule_digest: [u8; 32],
}

/// Exact replicated-command values that an ingress attestation must bind.
/// The peer commitment is intentionally taken from the signed statement for
/// this follower-side check, as it has already been bound to the authenticated
/// connection by ingress.
#[doc(hidden)]
pub struct RosterIngressAttestationRosterCommandInputV1<'a> {
    pub configuration_identity: &'a SessionConsensusIdentity,
    pub expected_scope: [u8; 32],
    pub expected_request_id: [u8; 16],
    pub expected_operation_tag: u8,
    pub expected_capsule_digest: [u8; 32],
    pub logical_time: Timestamp,
}

impl RosterIngressAttestationV1 {
    #[doc(hidden)]
    pub fn issue_from_signed_parts(
        root: &RosterAttestationTrustRootV1,
        certificate: RosterAttestationLeafCertificatePartsV1,
        input: &RosterIngressAttestationSigningInputV1,
        signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
    ) -> Result<Self, RosterAttestationError> {
        let certificate =
            RosterAttestationLeafCertificateV1::issue_from_signed_parts(root, certificate)?;
        if certificate.role()? != RosterAttestationCertificateRoleV1::TransportIngress {
            return Err(RosterAttestationError);
        }
        verify_digest_signature(&certificate.public_key, input.digest()?, &signature)?;
        Ok(Self {
            certificate,
            input: input.clone(),
            signature,
        })
    }

    #[doc(hidden)]
    pub fn verify(
        &self,
        root: &RosterAttestationTrustRootV1,
        expected: &RosterIngressAttestationVerificationInputV1<'_>,
        logical_time: Timestamp,
    ) -> Result<(), RosterAttestationError> {
        self.verify_connection_binding(root, expected)?;
        if logical_time < self.certificate.not_before
            || logical_time >= self.certificate.not_after
            || self.input.authenticated_at > logical_time
            || logical_time >= self.input.peer_certificate_expires_at
        {
            return Err(RosterAttestationError);
        }
        Ok(())
    }

    /// Verify the authenticated connection and exact request binding without
    /// making a wall-clock authority decision.
    ///
    /// A leader uses this check before proposing a roster mutation, avoiding a
    /// separate ReadIndex round. Every voter repeats the complete temporal
    /// verification at the mutation's replicated logical time before applying
    /// it, so an expired certificate or stale authority can never mutate the
    /// protected roster state.
    pub(crate) fn verify_connection_binding(
        &self,
        root: &RosterAttestationTrustRootV1,
        expected: &RosterIngressAttestationVerificationInputV1<'_>,
    ) -> Result<(), RosterAttestationError> {
        self.certificate.verify_root(root)?;
        if self.certificate.role()? != RosterAttestationCertificateRoleV1::TransportIngress
            || self.certificate.configuration_identity != *expected.configuration_identity
            || self.certificate.scope != expected.expected_scope
            || self.input.peer_identity_commitment != expected.expected_peer_identity_commitment
            || self.input.consumer_scope != expected.expected_scope
            || self.input.request_id != expected.expected_request_id
            || self.input.operation_tag != expected.expected_operation_tag
            || self.input.canonical_capsule_digest != expected.expected_capsule_digest
        {
            return Err(RosterAttestationError);
        }
        verify_digest_signature(
            &self.certificate.public_key,
            self.input.digest()?,
            &self.signature,
        )
    }

    /// Verify this retained envelope for a deterministic replicated roster
    /// command. The authenticated ingress service has already compared the
    /// statement's peer and request id with its connection; followers
    /// independently bind the root, configuration, scope, operation, exact
    /// reconstructed capsule, and replicated logical time.
    #[doc(hidden)]
    pub fn verify_roster_command(
        &self,
        root: &RosterAttestationTrustRootV1,
        expected: &RosterIngressAttestationRosterCommandInputV1<'_>,
    ) -> Result<(), RosterAttestationError> {
        let connection_binding = RosterIngressAttestationVerificationInputV1 {
            configuration_identity: expected.configuration_identity,
            expected_peer_identity_commitment: self.input.peer_identity_commitment,
            expected_scope: expected.expected_scope,
            expected_request_id: expected.expected_request_id,
            expected_operation_tag: expected.expected_operation_tag,
            expected_capsule_digest: expected.expected_capsule_digest,
        };
        self.verify(root, &connection_binding, expected.logical_time)
    }

    /// Return the exact outer consumer request id retained in the signed
    /// ingress statement. Command constructors compare it with the separate
    /// request-id field that came from the authenticated consumer envelope.
    #[doc(hidden)]
    pub const fn request_id(&self) -> [u8; 16] {
        self.input.request_id
    }

    /// Return the exact typed statement retained by this verified ingress
    /// envelope. The consensus ingress uses it to construct the separate V2
    /// admission provenance without re-creating any authenticated transport
    /// fields or introducing a self-referential capsule commitment.
    pub(crate) const fn signing_input(&self) -> &RosterIngressAttestationSigningInputV1 {
        &self.input
    }

    /// Exact bounded canonical command envelope.
    #[doc(hidden)]
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RosterAttestationError> {
        self.input.digest()?;
        self.certificate.validate_structure()?;
        canonical_signature(&self.signature)?;
        let bytes = postcard::to_allocvec(self).map_err(|_| RosterAttestationError)?;
        if bytes.len() > MAX_ROSTER_INGRESS_ATTESTATION_BYTES {
            return Err(RosterAttestationError);
        }
        Ok(bytes)
    }

    /// Decode only an exact canonical ingress statement. Root/certificate
    /// trust and command bindings are checked separately by `verify`.
    #[doc(hidden)]
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RosterAttestationError> {
        if bytes.is_empty() || bytes.len() > MAX_ROSTER_INGRESS_ATTESTATION_BYTES {
            return Err(RosterAttestationError);
        }
        let value: Self = postcard::from_bytes(bytes).map_err(|_| RosterAttestationError)?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RosterAttestationError);
        }
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for RosterIngressAttestationV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            certificate: RosterAttestationLeafCertificateV1,
            input: RosterIngressAttestationSigningInputV1,
            #[serde(with = "fixed_array_64")]
            signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
        }
        let wire = Wire::deserialize(deserializer)?;
        wire.input.digest().map_err(serde::de::Error::custom)?;
        canonical_signature(&wire.signature).map_err(serde::de::Error::custom)?;
        Ok(Self {
            certificate: wire.certificate,
            input: wire.input,
            signature: wire.signature,
        })
    }
}

impl fmt::Debug for RosterIngressAttestationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterIngressAttestationV1(<redacted>)")
    }
}

// V2 compact evidence is intentionally separate from the frozen V1 profile
// descriptor.  V1 retains its exact wire contract; V2 is an additive durable
// witness used only once a deterministic compactor removes raw bodies.

const COMPACT_ADMISSION_FIELD_OWNER: u8 = 1;
const COMPACT_ADMISSION_FIELD_STATE_TYPE: u8 = 2;
const COMPACT_ADMISSION_FIELD_PLAN: u8 = 3;
const COMPACT_ADMISSION_FIELD_CHECKPOINT: u8 = 4;
const COMPACT_ADMISSION_FIELD_RESULT: u8 = 5;

fn compact_admission_field_commitment(field: u8, bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_COMPACT_ADMISSION_FIELD_DOMAIN);
    hasher.update([field]);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn compact_owner_commitment(owner: &OwnerId) -> [u8; 32] {
    compact_admission_field_commitment(COMPACT_ADMISSION_FIELD_OWNER, owner.as_str().as_bytes())
}

fn compact_owner_commitment_from_canonical(owner: &[u8]) -> [u8; 32] {
    compact_admission_field_commitment(COMPACT_ADMISSION_FIELD_OWNER, owner)
}

fn compact_session_key_commitment_from_canonical(key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_KEY_BINDING_DOMAIN);
    update_len_prefixed(&mut hasher, key);
    hasher.finalize().into()
}

fn compact_tenant_scope_partition(scope: Scope, key: &SessionKey) -> [u8; 32] {
    tenant_scope_partition_commitment(scope, key)
}

fn compact_admission_slot(admission: &Admission) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_COMPACT_ADMISSION_SLOT_DOMAIN);
    hasher.update(admission.scope().digest());
    let key = admission.key().canonical_digest_input();
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key);
    hasher.update(admission.roster_id().as_bytes());
    hasher.finalize().into()
}

/// Stable commitment of exact canonical compact-admission bytes for durable
/// SQLite/index integration. The byte string remains opaque to diagnostics.
#[doc(hidden)]
pub fn roster_compact_admission_provenance_commitment(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_COMPACT_ADMISSION_COMMITMENT_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Stable commitment of exact canonical compact-terminal bytes for durable
/// SQLite/index integration. The byte string remains opaque to diagnostics.
#[doc(hidden)]
pub fn roster_compact_terminal_evidence_commitment(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_COMPACT_TERMINAL_COMMITMENT_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

/// One descriptor-free immutable admission member projection.
///
/// This is a signer preimage component, not accepted terminal evidence. The
/// only accepted compact evidence constructors verify a topology-certified
/// leaf signature over it.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterCompactAdmissionMemberProjectionV2 {
    pub ordinal: u8,
    pub member_operation_id: [u8; MEMBER_OPERATION_ID_BYTES],
    pub descriptor_length: u16,
    pub descriptor_commitment: [u8; 32],
    pub expected_member_version: u64,
}

impl RosterCompactAdmissionMemberProjectionV2 {
    fn validate(&self, expected_ordinal: usize) -> Result<(), RosterAttestationError> {
        if self.ordinal as usize != expected_ordinal
            || self.member_operation_id == [0; MEMBER_OPERATION_ID_BYTES]
            || self.descriptor_length == 0
            || self.descriptor_length as usize > MAX_DESCRIPTOR_BYTES
            || self.descriptor_commitment == [0; 32]
            || self.expected_member_version == 0
        {
            return Err(RosterAttestationError);
        }
        Ok(())
    }
}

impl fmt::Debug for RosterCompactAdmissionMemberProjectionV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterCompactAdmissionMemberProjectionV2(<redacted>)")
    }
}

/// Length-and-commitment projection of one compacted protected field.
#[doc(hidden)]
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterCompactFieldCommitmentV2 {
    pub length: u32,
    pub commitment: [u8; 32],
}

impl RosterCompactFieldCommitmentV2 {
    fn validate(self, maximum: usize) -> Result<(), RosterAttestationError> {
        if self.length as usize > maximum || self.commitment == [0; 32] {
            return Err(RosterAttestationError);
        }
        Ok(())
    }
}

impl fmt::Debug for RosterCompactFieldCommitmentV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterCompactFieldCommitmentV2(<redacted>)")
    }
}

/// Exact TransportIngress leaf-signature preimage for one compact immutable
/// admission projection. It contains only bounded commitments, never raw
/// session keys, owners, descriptors, plans, checkpoints, or results.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterCompactAdmissionProvenanceSigningInputV2 {
    pub profile: Profile,
    pub configuration_identity: SessionConsensusIdentity,
    pub certificate_subject_identity_commitment: [u8; 32],
    pub certificate_role: RosterAttestationCertificateRoleV1,
    pub scope: [u8; 32],
    pub tenant_scope_partition: [u8; 32],
    pub session_key_commitment: [u8; 32],
    pub admission_slot: [u8; 32],
    pub roster_id: [u8; ROSTER_ID_BYTES],
    pub admission_commitment: [u8; 32],
    pub members: Vec<RosterCompactAdmissionMemberProjectionV2>,
    pub established_mutation_tag: u8,
    pub established_state_type: Option<RosterCompactFieldCommitmentV2>,
    pub protected_plan: RosterCompactFieldCommitmentV2,
    pub protected_checkpoint: RosterCompactFieldCommitmentV2,
    pub protected_result: RosterCompactFieldCommitmentV2,
    pub logical_owner_commitment: [u8; 32],
    pub admission_fence: u64,
    pub expected_generation: u64,
    pub authority_scope: [u8; 32],
    pub authority_key_commitment: [u8; 32],
    pub authority_owner_commitment: [u8; 32],
    pub authority_fence: u64,
    pub authority_credential_id: u64,
    pub authority_generation: u64,
    pub authority_acquired_at: Timestamp,
    pub authority_expires_at: Timestamp,
    pub ingress: RosterIngressAttestationSigningInputV1,
}

impl RosterCompactAdmissionProvenanceSigningInputV2 {
    /// Produce the exact compact V2 TransportIngress leaf prehash.
    #[doc(hidden)]
    pub fn digest(&self) -> Result<[u8; 32], RosterAttestationError> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(ROSTER_COMPACT_ADMISSION_PROVENANCE_DOMAIN);
        hasher.update([2]);
        hasher.update(self.profile.schema().to_be_bytes());
        hasher.update(self.profile.consumer_revision().to_be_bytes());
        hasher.update(self.profile.digest());
        update_consensus_identity_attestation(&mut hasher, self.configuration_identity);
        hasher.update(self.certificate_subject_identity_commitment);
        hasher.update([self.certificate_role.tag()]);
        hasher.update(self.scope);
        hasher.update(self.tenant_scope_partition);
        hasher.update(self.session_key_commitment);
        hasher.update(self.admission_slot);
        hasher.update(self.roster_id);
        hasher.update(self.admission_commitment);
        hasher.update((self.members.len() as u64).to_be_bytes());
        for member in &self.members {
            hasher.update([member.ordinal]);
            hasher.update(member.member_operation_id);
            hasher.update(member.descriptor_length.to_be_bytes());
            hasher.update(member.descriptor_commitment);
            hasher.update(member.expected_member_version.to_be_bytes());
        }
        hasher.update([self.established_mutation_tag]);
        match self.established_state_type {
            Some(state_type) => {
                hasher.update([1]);
                hasher.update(state_type.length.to_be_bytes());
                hasher.update(state_type.commitment);
            }
            None => hasher.update([0]),
        }
        for field in [
            self.protected_plan,
            self.protected_checkpoint,
            self.protected_result,
        ] {
            hasher.update(field.length.to_be_bytes());
            hasher.update(field.commitment);
        }
        hasher.update(self.logical_owner_commitment);
        hasher.update(self.admission_fence.to_be_bytes());
        hasher.update(self.expected_generation.to_be_bytes());
        hasher.update(self.authority_scope);
        hasher.update(self.authority_key_commitment);
        hasher.update(self.authority_owner_commitment);
        hasher.update(self.authority_fence.to_be_bytes());
        hasher.update(self.authority_credential_id.to_be_bytes());
        hasher.update(self.authority_generation.to_be_bytes());
        update_timestamp_attestation(&mut hasher, self.authority_acquired_at);
        update_timestamp_attestation(&mut hasher, self.authority_expires_at);
        update_ingress_attestation_input(&mut hasher, &self.ingress);
        Ok(hasher.finalize().into())
    }

    fn validate(&self) -> Result<(), RosterAttestationError> {
        self.profile
            .validate()
            .map_err(|_| RosterAttestationError)?;
        if self.certificate_subject_identity_commitment == [0; 32]
            || self.certificate_role != RosterAttestationCertificateRoleV1::TransportIngress
            || self.scope == [0; 32]
            || self.tenant_scope_partition == [0; 32]
            || self.session_key_commitment == [0; 32]
            || self.admission_slot == [0; 32]
            || self.roster_id == [0; ROSTER_ID_BYTES]
            || self.admission_commitment == [0; 32]
            || self.members.is_empty()
            || self.members.len() > MAX_MEMBERS
            || self.logical_owner_commitment == [0; 32]
            || self.admission_fence == 0
            || self.expected_generation == 0
            || self.authority_scope == [0; 32]
            || self.authority_key_commitment == [0; 32]
            || self.authority_owner_commitment == [0; 32]
            || self.authority_fence == 0
            || self.authority_credential_id == 0
            || self.authority_generation == 0
            || self.authority_expires_at <= self.authority_acquired_at
            || self.authority_scope != self.scope
            || self.authority_key_commitment != self.session_key_commitment
            || self.authority_owner_commitment != self.logical_owner_commitment
            || self.authority_fence != self.admission_fence
            || self.authority_generation != self.expected_generation
        {
            return Err(RosterAttestationError);
        }
        let mut identities = BTreeSet::new();
        for (ordinal, member) in self.members.iter().enumerate() {
            member.validate(ordinal)?;
            if !identities.insert(member.member_operation_id) {
                return Err(RosterAttestationError);
            }
        }
        match (self.established_mutation_tag, self.established_state_type) {
            (ESTABLISHED_MUTATION_PUT_CHECKPOINT, Some(field)) => {
                field.validate(StateType::MAX_BYTES)?;
                if field.length == 0 {
                    return Err(RosterAttestationError);
                }
            }
            (ESTABLISHED_MUTATION_DELETE | ESTABLISHED_MUTATION_NO_OP, None) => {}
            _ => return Err(RosterAttestationError),
        }
        self.protected_plan.validate(MAX_PLAN_BYTES)?;
        self.protected_checkpoint.validate(MAX_CHECKPOINT_BYTES)?;
        self.protected_result.validate(MAX_RESULT_BYTES)?;
        self.ingress.digest()?;
        if self.ingress.consumer_scope != self.authority_scope {
            return Err(RosterAttestationError);
        }
        Ok(())
    }

    /// Construct the exact compact admission statement from an already
    /// authenticated V1 ingress input. This is exported only for the SDK's
    /// separate transport-signing crate; every caller field is recomputed
    /// from typed admission and authority values before the statement can be
    /// signed or accepted by consensus.
    #[doc(hidden)]
    pub(crate) fn for_admission(
        configuration_identity: SessionConsensusIdentity,
        admission: &Admission,
        original_authority: &AuthorityBinding,
        ingress: &RosterIngressAttestationSigningInputV1,
        certificate_subject_identity_commitment: [u8; 32],
    ) -> Result<Self, RosterAttestationError> {
        if original_authority.scope() != admission.scope()
            || original_authority.key() != admission.key()
            || original_authority.owner() != admission.logical_owner()
            || original_authority.fence() != admission.admission_fence()
            || original_authority.generation() != admission.expected_generation()
        {
            return Err(RosterAttestationError);
        }
        let state_type = admission
            .established_mutation()
            .state_type()
            .map(|state_type| RosterCompactFieldCommitmentV2 {
                length: state_type.as_str().len() as u32,
                commitment: compact_admission_field_commitment(
                    COMPACT_ADMISSION_FIELD_STATE_TYPE,
                    state_type.as_str().as_bytes(),
                ),
            });
        let field = |tag, bytes: &[u8]| RosterCompactFieldCommitmentV2 {
            length: bytes.len() as u32,
            commitment: compact_admission_field_commitment(tag, bytes),
        };
        let input = Self {
            profile: admission.profile(),
            configuration_identity,
            certificate_subject_identity_commitment,
            certificate_role: RosterAttestationCertificateRoleV1::TransportIngress,
            scope: admission.scope().digest(),
            tenant_scope_partition: compact_tenant_scope_partition(
                admission.scope(),
                admission.key(),
            ),
            session_key_commitment: session_key_commitment(admission.key()),
            admission_slot: compact_admission_slot(admission),
            roster_id: *admission.roster_id().as_bytes(),
            admission_commitment: admission.body_commitment(),
            members: admission
                .members()
                .iter()
                .map(|member| RosterCompactAdmissionMemberProjectionV2 {
                    ordinal: member.ordinal(),
                    member_operation_id: *member.operation_id().as_bytes(),
                    descriptor_length: member.descriptor().len() as u16,
                    descriptor_commitment: member.descriptor_commitment(),
                    expected_member_version: member.expected_version(),
                })
                .collect(),
            established_mutation_tag: admission.established_mutation().tag(),
            established_state_type: state_type,
            protected_plan: field(COMPACT_ADMISSION_FIELD_PLAN, admission.protected_plan()),
            protected_checkpoint: field(
                COMPACT_ADMISSION_FIELD_CHECKPOINT,
                admission.terminal_checkpoint(),
            ),
            protected_result: field(COMPACT_ADMISSION_FIELD_RESULT, admission.terminal_result()),
            logical_owner_commitment: compact_owner_commitment(admission.logical_owner()),
            admission_fence: admission.admission_fence().get(),
            expected_generation: admission.expected_generation().get(),
            authority_scope: original_authority.scope().digest(),
            authority_key_commitment: session_key_commitment(original_authority.key()),
            authority_owner_commitment: compact_owner_commitment(original_authority.owner()),
            authority_fence: original_authority.fence().get(),
            authority_credential_id: original_authority.credential_id(),
            authority_generation: original_authority.generation().get(),
            authority_acquired_at: original_authority.acquired_at(),
            authority_expires_at: original_authority.expires_at(),
            ingress: ingress.clone(),
        };
        input.validate()?;
        Ok(input)
    }

    /// Reconstruct the exact compact signer input from the canonical SDK
    /// admission and its authenticated lease fields. This is the narrow
    /// cross-crate seam used by the SDK transport layer; it never accepts a
    /// caller-authored disposition or emits consensus/store authority.
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn from_canonical_admission(
        configuration_identity: SessionConsensusIdentity,
        canonical_admission: &[u8],
        authority_scope: [u8; 32],
        authority_key: SessionKey,
        authority_owner: OwnerId,
        authority_fence: FenceToken,
        authority_credential_id: u64,
        authority_generation: Generation,
        authority_acquired_at: Timestamp,
        authority_expires_at: Timestamp,
        ingress: &RosterIngressAttestationSigningInputV1,
        certificate_subject_identity_commitment: [u8; 32],
    ) -> Result<Self, RosterAttestationError> {
        let admission = Admission::from_canonical_bytes(canonical_admission)
            .map_err(|_| RosterAttestationError)?;
        if admission.scope().digest() != authority_scope {
            return Err(RosterAttestationError);
        }
        let authority = AuthorityBinding::from_consensus_parts(
            authority_scope,
            authority_key,
            authority_owner,
            authority_fence,
            AuthorityLeaseMetadata::new(
                authority_credential_id,
                authority_generation,
                authority_acquired_at,
                authority_expires_at,
            ),
        )
        .map_err(|_| RosterAttestationError)?;
        Self::for_admission(
            configuration_identity,
            &admission,
            &authority,
            ingress,
            certificate_subject_identity_commitment,
        )
    }
}

impl fmt::Debug for RosterCompactAdmissionProvenanceSigningInputV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterCompactAdmissionProvenanceSigningInputV2(<redacted>)")
    }
}

/// Root-verifiable compact admission evidence. Its fields are private so a
/// consumer cannot manufacture an Applied-capable provenance object by a
/// struct literal or an unverified decoder.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RosterCompactAdmissionProvenanceV2 {
    certificate: RosterAttestationLeafCertificateV1,
    input: RosterCompactAdmissionProvenanceSigningInputV2,
    #[serde(with = "fixed_array_64")]
    signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
}

impl RosterCompactAdmissionProvenanceV2 {
    /// Issue only after a root-certified TransportIngress leaf has signed the
    /// exact compact projection. This verifies the supplied signature now;
    /// later verification additionally reconstructs the projection from typed
    /// admission and original-authority inputs.
    #[doc(hidden)]
    pub fn issue_from_signed_parts(
        root: &RosterAttestationTrustRootV1,
        certificate: RosterAttestationLeafCertificatePartsV1,
        input: &RosterCompactAdmissionProvenanceSigningInputV2,
        signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
    ) -> Result<Self, RosterAttestationError> {
        let certificate =
            RosterAttestationLeafCertificateV1::issue_from_signed_parts(root, certificate)?;
        if certificate.role()? != RosterAttestationCertificateRoleV1::TransportIngress
            || certificate.configuration_identity != input.configuration_identity
            || certificate.subject_identity_commitment
                != input.certificate_subject_identity_commitment
            || certificate.scope != input.authority_scope
        {
            return Err(RosterAttestationError);
        }
        verify_digest_signature(&certificate.public_key, input.digest()?, &signature)?;
        let value = Self {
            certificate,
            input: input.clone(),
            signature,
        };
        value.canonical_bytes()?;
        Ok(value)
    }

    /// Return exact bounded canonical bytes for persistence.
    #[doc(hidden)]
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RosterAttestationError> {
        self.input.validate()?;
        self.certificate.validate_structure()?;
        canonical_signature(&self.signature)?;
        let bytes = postcard::to_allocvec(self).map_err(|_| RosterAttestationError)?;
        if bytes.is_empty() || bytes.len() > MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES {
            return Err(RosterAttestationError);
        }
        Ok(bytes)
    }

    /// Decode only a byte-exact bounded canonical compact admission envelope.
    #[doc(hidden)]
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RosterAttestationError> {
        if bytes.is_empty() || bytes.len() > MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES {
            return Err(RosterAttestationError);
        }
        let value: Self = postcard::from_bytes(bytes).map_err(|_| RosterAttestationError)?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RosterAttestationError);
        }
        Ok(value)
    }

    /// Stable durable commitment of this exact canonical evidence.
    #[doc(hidden)]
    pub fn commitment(&self) -> Result<[u8; 32], RosterAttestationError> {
        Ok(roster_compact_admission_provenance_commitment(
            &self.canonical_bytes()?,
        ))
    }

    pub(crate) fn verify_for(
        &self,
        root: &RosterAttestationTrustRootV1,
        configuration_identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        admission: &Admission,
        original_authority: &AuthorityBinding,
        ingress: &RosterIngressAttestationSigningInputV1,
    ) -> Result<(), RosterAttestationError> {
        self.verify_historical_signature(root, configuration_identity)?;
        if self.certificate.scope != admission.scope().digest() || self.input.ingress != *ingress {
            return Err(RosterAttestationError);
        }
        if binding.scope.digest() != self.input.scope
            || binding.tenant_scope_partition != self.input.tenant_scope_partition
            || binding.session_key_commitment != self.input.session_key_commitment
            || binding.roster_id.as_bytes() != &self.input.roster_id
        {
            return Err(RosterAttestationError);
        }
        let expected = RosterCompactAdmissionProvenanceSigningInputV2::for_admission(
            configuration_identity,
            admission,
            original_authority,
            ingress,
            self.certificate.subject_identity_commitment,
        )?;
        if self.input != expected {
            return Err(RosterAttestationError);
        }
        Ok(())
    }

    fn verify_historical_signature(
        &self,
        root: &RosterAttestationTrustRootV1,
        configuration_identity: SessionConsensusIdentity,
    ) -> Result<(), RosterAttestationError> {
        self.input.validate()?;
        self.certificate.verify_root(root)?;
        if self.certificate.role()? != RosterAttestationCertificateRoleV1::TransportIngress
            || self.certificate.configuration_identity != configuration_identity
            || self.certificate.scope != self.input.authority_scope
            || self.certificate.subject_identity_commitment
                != self.input.certificate_subject_identity_commitment
            || self.input.ingress.authenticated_at < self.certificate.not_before
            || self.input.ingress.authenticated_at >= self.certificate.not_after
            || self.input.ingress.authenticated_at >= self.input.ingress.peer_certificate_expires_at
        {
            return Err(RosterAttestationError);
        }
        verify_digest_signature(
            &self.certificate.public_key,
            self.input.digest()?,
            &self.signature,
        )
    }

    fn input(&self) -> &RosterCompactAdmissionProvenanceSigningInputV2 {
        &self.input
    }
}

impl<'de> Deserialize<'de> for RosterCompactAdmissionProvenanceV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            certificate: RosterAttestationLeafCertificateV1,
            input: RosterCompactAdmissionProvenanceSigningInputV2,
            #[serde(with = "fixed_array_64")]
            signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
        }
        let wire = Wire::deserialize(deserializer)?;
        wire.input.validate().map_err(serde::de::Error::custom)?;
        canonical_signature(&wire.signature).map_err(serde::de::Error::custom)?;
        Ok(Self {
            certificate: wire.certificate,
            input: wire.input,
            signature: wire.signature,
        })
    }
}

impl fmt::Debug for RosterCompactAdmissionProvenanceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterCompactAdmissionProvenanceV2(<redacted>)")
    }
}

/// Crate-private exact inputs for historical compact-admission verification.
/// `original_authority` is deliberately not a current successor lease: a
/// higher execution fence must not rewrite admission provenance.
pub(crate) struct CompactAdmissionProvenanceVerificationV2<'a> {
    pub(crate) root: &'a RosterAttestationTrustRootV1,
    pub(crate) configuration_identity: SessionConsensusIdentity,
    pub(crate) binding: RequestBindingKey,
    pub(crate) admission: &'a Admission,
    pub(crate) original_authority: &'a AuthorityBinding,
    pub(crate) ingress: &'a RosterIngressAttestationSigningInputV1,
    pub(crate) provenance: &'a RosterCompactAdmissionProvenanceV2,
}

/// Crate-private inputs for rechecking compact admission evidence retained by
/// durable roster history. The ingress projection intentionally comes only
/// from the signed compact provenance, never from a retrying caller.
pub(crate) struct HistoricalCompactAdmissionProvenanceVerificationV2<'a> {
    pub(crate) root: &'a RosterAttestationTrustRootV1,
    pub(crate) configuration_identity: SessionConsensusIdentity,
    pub(crate) binding: RequestBindingKey,
    pub(crate) admission: &'a Admission,
    pub(crate) original_authority: &'a AuthorityBinding,
    pub(crate) provenance: &'a RosterCompactAdmissionProvenanceV2,
}

/// Verify compact admission evidence against the exact original typed values.
pub(crate) fn verify_compact_admission_provenance_v2(
    verification: CompactAdmissionProvenanceVerificationV2<'_>,
) -> Result<(), RosterAttestationError> {
    verification.provenance.verify_for(
        verification.root,
        verification.configuration_identity,
        verification.binding,
        verification.admission,
        verification.original_authority,
        verification.ingress,
    )
}

/// Revalidate immutable compact admission evidence from durable history.
///
/// The stored statement embeds the ingress projection that was signed with
/// the original authority. Retries can authenticate a different ingress and
/// provenance statement, but they must never select the projection used to
/// validate retained history.
pub(crate) fn verify_historical_compact_admission_provenance_v2(
    verification: HistoricalCompactAdmissionProvenanceVerificationV2<'_>,
) -> Result<(), RosterAttestationError> {
    let ingress = &verification.provenance.input().ingress;
    verification.provenance.verify_for(
        verification.root,
        verification.configuration_identity,
        verification.binding,
        verification.admission,
        verification.original_authority,
        ingress,
    )
}

/// Crate-private verifier inputs for a tombstone whose full admission bytes
/// have been reclaimed.  The signed compact provenance is the only durable
/// source for its stable slot and immutable original-authority projection.
pub(crate) struct CompactedTombstoneHistoryVerificationV2<'a> {
    pub(crate) root: &'a RosterAttestationTrustRootV1,
    pub(crate) configuration_identity: SessionConsensusIdentity,
    pub(crate) binding: RequestBindingKey,
    pub(crate) tombstone: &'a TerminalConflictTombstone,
    pub(crate) admission_provenance: &'a RosterCompactAdmissionProvenanceV2,
    pub(crate) terminal_evidence: &'a RosterCompactTerminalEvidenceV2,
    pub(crate) original_owner: &'a OwnerId,
    pub(crate) original_fence: u64,
    pub(crate) original_credential_id: u64,
    pub(crate) original_generation: u64,
    pub(crate) original_acquired_at: Timestamp,
    pub(crate) original_expires_at: Timestamp,
}

/// Authenticated stable slots reconstructed from reclaimed tombstone history.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompactedTombstoneHistorySlots {
    stable_slot: [u8; 32],
    terminal_slot: [u8; 32],
}

impl CompactedTombstoneHistorySlots {
    pub(crate) const fn stable_slot(self) -> [u8; 32] {
        self.stable_slot
    }

    pub(crate) const fn terminal_slot(self) -> [u8; 32] {
        self.terminal_slot
    }
}

/// Re-authenticate the compact history retained after admission bytes age out.
///
/// This deliberately reconstructs no `Admission`: it proves the binding,
/// stable slot, original-authority projection, compact terminal signatures,
/// and tombstone commitments from the signed compact frames themselves.
pub(crate) fn verify_compacted_tombstone_history_v2(
    verification: CompactedTombstoneHistoryVerificationV2<'_>,
) -> Result<CompactedTombstoneHistorySlots, RosterAttestationError> {
    let CompactedTombstoneHistoryVerificationV2 {
        root,
        configuration_identity,
        binding,
        tombstone,
        admission_provenance,
        terminal_evidence,
        original_owner,
        original_fence,
        original_credential_id,
        original_generation,
        original_acquired_at,
        original_expires_at,
    } = verification;
    tombstone.validate().map_err(|_| RosterAttestationError)?;
    admission_provenance.verify_historical_signature(root, configuration_identity)?;
    let admission = admission_provenance.input();
    if admission.scope != binding.scope.digest()
        || admission.tenant_scope_partition != binding.tenant_scope_partition
        || admission.session_key_commitment != binding.session_key_commitment
        || admission.roster_id != *binding.roster_id.as_bytes()
        || admission.admission_commitment != tombstone.admission_body_commitment
        || admission.admission_fence != tombstone.admission_fence
        || admission.expected_generation != tombstone.expected_generation
        || admission.authority_scope != binding.scope.digest()
        || admission.authority_key_commitment != binding.session_key_commitment
        || admission.authority_owner_commitment != compact_owner_commitment(original_owner)
        || admission.authority_fence != original_fence
        || admission.authority_credential_id != original_credential_id
        || admission.authority_generation != original_generation
        || admission.authority_acquired_at != original_acquired_at
        || admission.authority_expires_at != original_expires_at
    {
        return Err(RosterAttestationError);
    }
    let request = RequestId {
        history_epoch: binding.history_epoch,
        roster_id: binding.roster_id,
        body_commitment: admission.admission_commitment,
    };
    let terminal_slot = command_id(TERMINAL_SLOT_DOMAIN, binding);
    terminal_evidence.validate_structure()?;
    terminal_evidence.certificate.verify_root(root)?;
    let terminal = &terminal_evidence.binding;
    if terminal_evidence.certificate.role()? != RosterAttestationCertificateRoleV1::Executor
        || terminal_evidence.certificate.configuration_identity != configuration_identity
        || terminal_evidence.certificate.scope != terminal.authority_scope
        || terminal_evidence.certificate.subject_identity_commitment
            != terminal.certificate_subject_identity_commitment
        || terminal.profile != admission.profile
        || terminal.configuration_identity != configuration_identity
        || terminal.admission_provenance_commitment != admission_provenance.commitment()?
        || terminal.binding != binding.to_bytes()
        || terminal.registration_handle == [0; 32]
        || terminal.registration_request_id != request.to_bytes()
        || terminal.registration_terminal_slot != terminal_slot
        || terminal.roster_id != admission.roster_id
        || terminal.admission_commitment != admission.admission_commitment
        || terminal.terminal_phase_tag != tombstone.phase_tag
        || terminal.terminal_body_commitment != tombstone.terminal_body_commitment
        || terminal.terminal_checkpoint != admission.protected_checkpoint
        || terminal.terminal_result != admission.protected_result
        || terminal.authority_scope != binding.scope.digest()
        || terminal.authority_key_commitment != binding.session_key_commitment
        || terminal.authority_owner_commitment != compact_owner_commitment(original_owner)
        || terminal.authority_generation != original_generation
        || terminal.authority_fence < original_fence
        || terminal.authority_credential_id == 0
        || terminal.authority_expires_at <= terminal.authority_acquired_at
        || terminal_evidence.proofs.len() != admission.members.len()
    {
        return Err(RosterAttestationError);
    }
    for (proof, admitted) in terminal_evidence.proofs.iter().zip(&admission.members) {
        proof.provider_certificate.verify_root(root)?;
        if proof.provider_certificate.configuration_identity != configuration_identity
            || proof.provider_certificate.scope != terminal.authority_scope
        {
            return Err(RosterAttestationError);
        }
        if proof.member.ordinal != admitted.ordinal
            || proof.member.member_operation_id != admitted.member_operation_id
            || proof.member.descriptor_length != admitted.descriptor_length
            || proof.member.descriptor_commitment != admitted.descriptor_commitment
            || proof.member.expected_member_version != admitted.expected_member_version
        {
            return Err(RosterAttestationError);
        }
        verify_digest_signature(
            &proof.provider_certificate.public_key,
            provider_receipt_compact_digest(terminal, &proof.member, &proof.provider_certificate)?,
            &proof.provider_signature,
        )?;
        let signed = RosterCompactTerminalMemberSigningInputV2 {
            binding: terminal.clone(),
            member: proof.member.clone(),
        };
        verify_digest_signature(
            &terminal_evidence.certificate.public_key,
            signed.digest()?,
            &proof.signature,
        )?;
    }
    Ok(CompactedTombstoneHistorySlots {
        stable_slot: admission.admission_slot,
        terminal_slot,
    })
}

fn update_ingress_attestation_input(
    hasher: &mut Sha256,
    ingress: &RosterIngressAttestationSigningInputV1,
) {
    hasher.update(ingress.peer_identity_commitment);
    hasher.update(ingress.consumer_scope);
    hasher.update(ingress.request_id);
    hasher.update([ingress.operation_tag]);
    hasher.update(ingress.canonical_capsule_digest);
    update_timestamp_attestation(hasher, ingress.authenticated_at);
    update_timestamp_attestation(hasher, ingress.peer_certificate_expires_at);
    hasher.update(ingress.material_generation.to_be_bytes());
    hasher.update(ingress.handshake_epoch.to_be_bytes());
}

/// Common compact terminal binding included in every V2 member signature.
/// It deliberately retains commitments only, so a follower can verify the
/// terminal after descriptors, provider evidence, and protected payload bytes
/// have been compacted away.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterCompactTerminalEvidenceBindingV2 {
    pub profile: Profile,
    pub configuration_identity: SessionConsensusIdentity,
    pub certificate_subject_identity_commitment: [u8; 32],
    pub certificate_role: RosterAttestationCertificateRoleV1,
    pub admission_provenance_commitment: [u8; 32],
    #[serde(with = "fixed_array_120")]
    pub binding: [u8; 120],
    pub registration_handle: [u8; 32],
    #[serde(with = "fixed_array_56")]
    pub registration_request_id: [u8; 56],
    pub registration_terminal_slot: [u8; 32],
    pub roster_id: [u8; ROSTER_ID_BYTES],
    pub admission_commitment: [u8; 32],
    pub terminal_phase_tag: u8,
    pub terminal_body_commitment: [u8; 32],
    pub terminal_checkpoint: RosterCompactFieldCommitmentV2,
    pub terminal_result: RosterCompactFieldCommitmentV2,
    pub authority_scope: [u8; 32],
    pub authority_key_commitment: [u8; 32],
    pub authority_owner_commitment: [u8; 32],
    pub authority_fence: u64,
    pub authority_credential_id: u64,
    pub authority_generation: u64,
    pub authority_acquired_at: Timestamp,
    pub authority_expires_at: Timestamp,
}

impl RosterCompactTerminalEvidenceBindingV2 {
    fn validate(&self) -> Result<(), RosterAttestationError> {
        self.profile
            .validate()
            .map_err(|_| RosterAttestationError)?;
        let binding =
            RequestBindingKey::from_bytes(self.binding).map_err(|_| RosterAttestationError)?;
        let phase = Phase::from_tag(self.terminal_phase_tag).map_err(|_| RosterAttestationError)?;
        let _ = phase;
        if self.certificate_subject_identity_commitment == [0; 32]
            || self.certificate_role != RosterAttestationCertificateRoleV1::Executor
            || self.admission_provenance_commitment == [0; 32]
            || self.registration_handle == [0; 32]
            || self.registration_terminal_slot == [0; 32]
            || self.roster_id == [0; ROSTER_ID_BYTES]
            || self.admission_commitment == [0; 32]
            || self.terminal_body_commitment == [0; 32]
            || self.authority_scope == [0; 32]
            || self.authority_key_commitment == [0; 32]
            || self.authority_owner_commitment == [0; 32]
            || self.authority_fence == 0
            || self.authority_credential_id == 0
            || self.authority_generation == 0
            || self.authority_expires_at <= self.authority_acquired_at
            || binding.roster_id.as_bytes() != &self.roster_id
            || binding.scope.digest() != self.authority_scope
            || binding.session_key_commitment != self.authority_key_commitment
        {
            return Err(RosterAttestationError);
        }
        self.terminal_checkpoint.validate(MAX_CHECKPOINT_BYTES)?;
        self.terminal_result.validate(MAX_RESULT_BYTES)?;
        compact_registration_matches(self.binding, self)?;
        Ok(())
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn for_terminal(
        configuration_identity: SessionConsensusIdentity,
        binding: RequestBindingKey,
        registration: BackendRegistration,
        admission_provenance: &RosterCompactAdmissionProvenanceV2,
        admission: &Admission,
        authority: &AuthorityBinding,
        terminal: &TerminalRecord,
        certificate_subject_identity_commitment: [u8; 32],
    ) -> Result<Self, RosterAttestationError> {
        binding.validate().map_err(|_| RosterAttestationError)?;
        validate_attestation_registration(binding, registration, admission)?;
        terminal
            .validate_for(admission)
            .map_err(|_| RosterAttestationError)?;
        if binding.scope != admission.scope()
            || binding.roster_id != admission.roster_id()
            || authority.scope() != admission.scope()
            || authority.key() != admission.key()
            || authority.credential_id() == 0
            || authority.fence().get() == 0
            || authority.generation().get() == 0
            || authority.expires_at() <= authority.acquired_at()
        {
            return Err(RosterAttestationError);
        }
        let (registration_handle, request_id, terminal_slot) = registration.consensus_parts();
        let field = |tag, bytes: &[u8]| RosterCompactFieldCommitmentV2 {
            length: bytes.len() as u32,
            commitment: compact_admission_field_commitment(tag, bytes),
        };
        let value = Self {
            profile: admission.profile(),
            configuration_identity,
            certificate_subject_identity_commitment,
            certificate_role: RosterAttestationCertificateRoleV1::Executor,
            admission_provenance_commitment: admission_provenance.commitment()?,
            binding: binding.to_bytes(),
            registration_handle,
            registration_request_id: request_id.to_bytes(),
            registration_terminal_slot: *terminal_slot.as_bytes(),
            roster_id: *admission.roster_id().as_bytes(),
            admission_commitment: admission.body_commitment(),
            terminal_phase_tag: terminal.phase().map_err(|_| RosterAttestationError)?.tag(),
            terminal_body_commitment: terminal.body_commitment(),
            terminal_checkpoint: field(
                COMPACT_ADMISSION_FIELD_CHECKPOINT,
                admission.terminal_checkpoint(),
            ),
            terminal_result: field(COMPACT_ADMISSION_FIELD_RESULT, admission.terminal_result()),
            authority_scope: authority.scope().digest(),
            authority_key_commitment: session_key_commitment(authority.key()),
            authority_owner_commitment: compact_owner_commitment(authority.owner()),
            authority_fence: authority.fence().get(),
            authority_credential_id: authority.credential_id(),
            authority_generation: authority.generation().get(),
            authority_acquired_at: authority.acquired_at(),
            authority_expires_at: authority.expires_at(),
        };
        value.validate()?;
        Ok(value)
    }

    /// Construct the compact common binding from the exact V1 terminal input
    /// that the SDK already produced, plus the immutable admission provenance
    /// and protected bytes retained by the admission. This narrow bridge lets
    /// a separate SDK crate issue V2 member signatures without reproducing
    /// private commitment domains or gaining a generic signing capability.
    #[doc(hidden)]
    pub fn from_terminal_v1_input(
        admission_provenance: &RosterCompactAdmissionProvenanceV2,
        protected_checkpoint: &[u8],
        protected_result: &[u8],
        input: &RosterTerminalAttestationSigningInputV1,
    ) -> Result<Self, RosterAttestationError> {
        input.digest()?;
        if input.certificate_role != RosterAttestationCertificateRoleV1::Executor
            || protected_checkpoint.len() > MAX_CHECKPOINT_BYTES
            || protected_result.len() > MAX_RESULT_BYTES
        {
            return Err(RosterAttestationError);
        }
        let field =
            |tag, bytes: &[u8]| -> Result<RosterCompactFieldCommitmentV2, RosterAttestationError> {
                Ok(RosterCompactFieldCommitmentV2 {
                    length: u32::try_from(bytes.len()).map_err(|_| RosterAttestationError)?,
                    commitment: compact_admission_field_commitment(tag, bytes),
                })
            };
        let value = Self {
            profile: input.profile,
            configuration_identity: input.configuration_identity,
            certificate_subject_identity_commitment: input.certificate_subject_identity_commitment,
            certificate_role: RosterAttestationCertificateRoleV1::Executor,
            admission_provenance_commitment: admission_provenance.commitment()?,
            binding: input.binding,
            registration_handle: input.registration_handle,
            registration_request_id: input.registration_request_id,
            registration_terminal_slot: input.registration_terminal_slot,
            roster_id: input.roster_id,
            admission_commitment: input.admission_commitment,
            terminal_phase_tag: input.terminal_phase.tag(),
            terminal_body_commitment: input.terminal_body_commitment,
            terminal_checkpoint: field(COMPACT_ADMISSION_FIELD_CHECKPOINT, protected_checkpoint)?,
            terminal_result: field(COMPACT_ADMISSION_FIELD_RESULT, protected_result)?,
            authority_scope: input.authority_scope,
            authority_key_commitment: compact_session_key_commitment_from_canonical(
                &input.authority_key_canonical,
            ),
            authority_owner_commitment: compact_owner_commitment_from_canonical(
                &input.authority_owner,
            ),
            authority_fence: input.authority_fence,
            authority_credential_id: input.authority_credential_id,
            authority_generation: input.authority_generation,
            authority_acquired_at: input.authority_acquired_at,
            authority_expires_at: input.authority_expires_at,
        };
        value.validate()?;
        Ok(value)
    }
}

impl fmt::Debug for RosterCompactTerminalEvidenceBindingV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterCompactTerminalEvidenceBindingV2(<redacted>)")
    }
}

/// Descriptor- and evidence-free member input signed directly by an Executor
/// leaf. A provider cannot express Pending, Indeterminate, or unreconciled
/// state in this closed outcome vocabulary.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RosterCompactTerminalMemberProjectionV2 {
    pub ordinal: u8,
    pub member_operation_id: [u8; MEMBER_OPERATION_ID_BYTES],
    pub descriptor_length: u16,
    pub descriptor_commitment: [u8; 32],
    pub expected_member_version: u64,
    pub admission_generation: u64,
    pub proof_epoch: u64,
    pub provider_operation: RosterProviderOperationV1,
    pub outcome: RosterProviderOutcomeV1,
    pub evidence_length: u16,
    pub evidence_commitment: [u8; 32],
    pub stable_proof_commitment: [u8; 32],
}

impl RosterCompactTerminalMemberProjectionV2 {
    /// Project one exact raw V1 executor proof input into its independently
    /// signed compact V2 form. The caller supplies the immutable terminal
    /// proof commitment already bound into the prepared terminal body; raw
    /// descriptor and provider evidence bytes never enter the compact row.
    #[doc(hidden)]
    pub fn from_terminal_v1_input(
        input: &RosterTerminalAttestationSigningInputV1,
        stable_proof_commitment: [u8; 32],
    ) -> Result<Self, RosterAttestationError> {
        input.digest()?;
        let value = Self {
            ordinal: input.ordinal,
            member_operation_id: input.member_operation_id,
            descriptor_length: u16::try_from(input.descriptor.len())
                .map_err(|_| RosterAttestationError)?,
            descriptor_commitment: input.descriptor_commitment,
            expected_member_version: input.expected_member_version,
            admission_generation: input.admission_generation,
            proof_epoch: input.proof_epoch,
            provider_operation: input.provider_operation,
            outcome: input.outcome,
            evidence_length: u16::try_from(input.evidence.len())
                .map_err(|_| RosterAttestationError)?,
            evidence_commitment: roster_executor_evidence_commitment(&input.evidence),
            stable_proof_commitment,
        };
        value.validate(input.ordinal as usize, input.terminal_phase)?;
        Ok(value)
    }

    fn validate(
        &self,
        expected_ordinal: usize,
        phase: Phase,
    ) -> Result<(), RosterAttestationError> {
        if self.ordinal as usize != expected_ordinal
            || self.ordinal as usize >= MAX_MEMBERS
            || self.member_operation_id == [0; MEMBER_OPERATION_ID_BYTES]
            || self.descriptor_length == 0
            || self.descriptor_length as usize > MAX_DESCRIPTOR_BYTES
            || self.descriptor_commitment == [0; 32]
            || self.expected_member_version == 0
            || self.admission_generation == 0
            || self.proof_epoch == 0
            || self.evidence_length == 0
            || self.evidence_length as usize > MAX_EXECUTOR_PROOF_EVIDENCE_BYTES
            || self.evidence_commitment == [0; 32]
            || self.stable_proof_commitment == [0; 32]
            || !attested_provider_outcome_allowed(self.provider_operation, self.outcome)
            || self.outcome.phase() != phase
        {
            return Err(RosterAttestationError);
        }
        Ok(())
    }
}

impl fmt::Debug for RosterCompactTerminalMemberProjectionV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterCompactTerminalMemberProjectionV2(<redacted>)")
    }
}

/// Exact Executor leaf-signature preimage for one compact terminal member.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct RosterCompactTerminalMemberSigningInputV2 {
    pub binding: RosterCompactTerminalEvidenceBindingV2,
    pub member: RosterCompactTerminalMemberProjectionV2,
}

impl RosterCompactTerminalMemberSigningInputV2 {
    /// Produce the exact P-256 prehash for one compact V2 member evidence.
    #[doc(hidden)]
    pub fn digest(&self) -> Result<[u8; 32], RosterAttestationError> {
        self.binding.validate()?;
        let phase =
            Phase::from_tag(self.binding.terminal_phase_tag).map_err(|_| RosterAttestationError)?;
        self.member.validate(self.member.ordinal as usize, phase)?;
        let mut hasher = Sha256::new();
        hasher.update(ROSTER_COMPACT_TERMINAL_EVIDENCE_DOMAIN);
        hasher.update([2]);
        update_compact_terminal_binding(&mut hasher, &self.binding);
        update_compact_terminal_member(&mut hasher, &self.member);
        Ok(hasher.finalize().into())
    }
}

impl fmt::Debug for RosterCompactTerminalMemberSigningInputV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterCompactTerminalMemberSigningInputV2(<redacted>)")
    }
}

/// One pre-signed compact terminal member component. Supplying this component
/// alone never authorizes a terminal; issuance verifies a root-certified
/// Executor certificate and the exact per-member leaf preimage.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq)]
pub struct RosterCompactTerminalMemberProofPartsV2 {
    pub member: RosterCompactTerminalMemberProjectionV2,
    /// Root-signed Provider leaf certificate retained after raw evidence is
    /// compacted so followers can independently reverify the receipt.
    pub provider_certificate: RosterAttestationLeafCertificatePartsV1,
    /// Provider signature over the receipt domain and the compact evidence
    /// commitment (not the selected terminal phase/body).
    pub provider_signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
    pub signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct RosterCompactTerminalMemberProofV2 {
    member: RosterCompactTerminalMemberProjectionV2,
    provider_certificate: RosterAttestationLeafCertificateV1,
    #[serde(with = "fixed_array_64")]
    provider_signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
    #[serde(with = "fixed_array_64")]
    signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
}

impl RosterCompactTerminalMemberProofV2 {
    fn from_parts(
        parts: RosterCompactTerminalMemberProofPartsV2,
    ) -> Result<Self, RosterAttestationError> {
        let provider_certificate =
            RosterAttestationLeafCertificateV1::from_parts(parts.provider_certificate)?;
        if provider_certificate.role()? != RosterAttestationCertificateRoleV1::Provider {
            return Err(RosterAttestationError);
        }
        canonical_signature(&parts.provider_signature)?;
        canonical_signature(&parts.signature)?;
        Ok(Self {
            member: parts.member,
            provider_certificate,
            provider_signature: parts.provider_signature,
            signature: parts.signature,
        })
    }
}

impl<'de> Deserialize<'de> for RosterCompactTerminalMemberProofV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            member: RosterCompactTerminalMemberProjectionV2,
            provider_certificate: RosterAttestationLeafCertificateV1,
            #[serde(with = "fixed_array_64")]
            provider_signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
            #[serde(with = "fixed_array_64")]
            signature: [u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            member: wire.member,
            provider_certificate: wire.provider_certificate,
            provider_signature: wire.provider_signature,
            signature: wire.signature,
        };
        value
            .validate_structure()
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl RosterCompactTerminalMemberProofV2 {
    fn validate_structure(&self) -> Result<(), RosterAttestationError> {
        self.provider_certificate.validate_structure()?;
        if self.provider_certificate.role()? != RosterAttestationCertificateRoleV1::Provider {
            return Err(RosterAttestationError);
        }
        canonical_signature(&self.provider_signature)?;
        canonical_signature(&self.signature).map(|_| ())
    }
}

/// Root-verifiable compact terminal evidence with one direct Executor leaf
/// signature per ordered member. Raw provider evidence is represented only by
/// its length and domain-separated commitment.
#[doc(hidden)]
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RosterCompactTerminalEvidenceV2 {
    certificate: RosterAttestationLeafCertificateV1,
    binding: RosterCompactTerminalEvidenceBindingV2,
    proofs: Vec<RosterCompactTerminalMemberProofV2>,
}

impl RosterCompactTerminalEvidenceV2 {
    /// Issue only root-certified, directly leaf-signed compact evidence.
    #[doc(hidden)]
    pub fn issue_from_signed_parts(
        root: &RosterAttestationTrustRootV1,
        certificate: RosterAttestationLeafCertificatePartsV1,
        binding: &RosterCompactTerminalEvidenceBindingV2,
        proofs: Vec<RosterCompactTerminalMemberProofPartsV2>,
    ) -> Result<Self, RosterAttestationError> {
        let certificate =
            RosterAttestationLeafCertificateV1::issue_from_signed_parts(root, certificate)?;
        if certificate.role()? != RosterAttestationCertificateRoleV1::Executor
            || certificate.configuration_identity != binding.configuration_identity
            || certificate.subject_identity_commitment
                != binding.certificate_subject_identity_commitment
            || certificate.scope != binding.authority_scope
        {
            return Err(RosterAttestationError);
        }
        binding.validate()?;
        if proofs.is_empty() || proofs.len() > MAX_MEMBERS {
            return Err(RosterAttestationError);
        }
        let proofs = proofs
            .into_iter()
            .enumerate()
            .map(|(ordinal, proof)| {
                let input = RosterCompactTerminalMemberSigningInputV2 {
                    binding: binding.clone(),
                    member: proof.member.clone(),
                };
                proof.member.validate(
                    ordinal,
                    Phase::from_tag(binding.terminal_phase_tag)
                        .map_err(|_| RosterAttestationError)?,
                )?;
                let provider = RosterAttestationLeafCertificateV1::from_parts(
                    proof.provider_certificate.clone(),
                )?;
                provider.verify_root(root)?;
                verify_digest_signature(
                    &provider.public_key,
                    provider_receipt_compact_digest(binding, &proof.member, &provider)?,
                    &proof.provider_signature,
                )?;
                verify_digest_signature(
                    &certificate.public_key,
                    input.digest()?,
                    &proof.signature,
                )?;
                RosterCompactTerminalMemberProofV2::from_parts(proof)
            })
            .collect::<Result<Vec<_>, RosterAttestationError>>()?;
        let value = Self {
            certificate,
            binding: binding.clone(),
            proofs,
        };
        value.canonical_bytes()?;
        Ok(value)
    }

    /// Return exact bounded canonical bytes for persistence.
    #[doc(hidden)]
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RosterAttestationError> {
        self.validate_structure()?;
        let bytes = postcard::to_allocvec(self).map_err(|_| RosterAttestationError)?;
        if bytes.is_empty() || bytes.len() > MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES {
            return Err(RosterAttestationError);
        }
        Ok(bytes)
    }

    /// Decode only byte-exact bounded canonical terminal evidence.
    #[doc(hidden)]
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, RosterAttestationError> {
        if bytes.is_empty() || bytes.len() > MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES {
            return Err(RosterAttestationError);
        }
        let value: Self = postcard::from_bytes(bytes).map_err(|_| RosterAttestationError)?;
        value.validate_structure()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RosterAttestationError);
        }
        Ok(value)
    }

    /// Stable durable commitment of this exact canonical evidence.
    #[doc(hidden)]
    pub fn commitment(&self) -> Result<[u8; 32], RosterAttestationError> {
        Ok(roster_compact_terminal_evidence_commitment(
            &self.canonical_bytes()?,
        ))
    }

    fn validate_structure(&self) -> Result<(), RosterAttestationError> {
        self.certificate.validate_structure()?;
        self.binding.validate()?;
        if self.proofs.is_empty() || self.proofs.len() > MAX_MEMBERS {
            return Err(RosterAttestationError);
        }
        let phase =
            Phase::from_tag(self.binding.terminal_phase_tag).map_err(|_| RosterAttestationError)?;
        let mut ids = BTreeSet::new();
        for (ordinal, proof) in self.proofs.iter().enumerate() {
            proof.member.validate(ordinal, phase)?;
            proof.validate_structure()?;
            if !ids.insert(proof.member.member_operation_id) {
                return Err(RosterAttestationError);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_compact_for(
        &self,
        root: &RosterAttestationTrustRootV1,
        configuration_identity: SessionConsensusIdentity,
        logical_time: Timestamp,
        binding: RequestBindingKey,
        registration: BackendRegistration,
        admission_provenance: &RosterCompactAdmissionProvenanceV2,
        committing_authority: &AuthorityBinding,
    ) -> Result<(), RosterAttestationError> {
        self.validate_structure()?;
        self.certificate.verify_root(root)?;
        admission_provenance.verify_historical_signature(root, configuration_identity)?;
        if self.certificate.role()? != RosterAttestationCertificateRoleV1::Executor
            || self.certificate.configuration_identity != configuration_identity
            || self.certificate.scope != self.binding.authority_scope
            || self.certificate.subject_identity_commitment
                != self.binding.certificate_subject_identity_commitment
            || logical_time < self.certificate.not_before
            || logical_time >= self.certificate.not_after
            || self.binding.binding != binding.to_bytes()
            || self.binding.configuration_identity != configuration_identity
            || self.binding.admission_provenance_commitment != admission_provenance.commitment()?
        {
            return Err(RosterAttestationError);
        }
        verify_compact_terminal_chain(
            &self.binding,
            &self.proofs,
            binding,
            registration,
            admission_provenance,
        )?;
        if committing_authority.scope().digest() != self.binding.authority_scope
            || session_key_commitment(committing_authority.key())
                != self.binding.authority_key_commitment
            || compact_owner_commitment(committing_authority.owner())
                != self.binding.authority_owner_commitment
            || committing_authority.fence().get() != self.binding.authority_fence
            || committing_authority.credential_id() != self.binding.authority_credential_id
            || committing_authority.generation().get() != self.binding.authority_generation
            || committing_authority.acquired_at() != self.binding.authority_acquired_at
            || committing_authority.expires_at() != self.binding.authority_expires_at
            || logical_time < committing_authority.acquired_at()
            || logical_time >= committing_authority.expires_at()
        {
            return Err(RosterAttestationError);
        }
        for proof in &self.proofs {
            proof.provider_certificate.verify_root(root)?;
            if proof.provider_certificate.configuration_identity != configuration_identity
                || proof.provider_certificate.scope != self.binding.authority_scope
                || logical_time < proof.provider_certificate.not_before
                || logical_time >= proof.provider_certificate.not_after
            {
                return Err(RosterAttestationError);
            }
            verify_digest_signature(
                &proof.provider_certificate.public_key,
                provider_receipt_compact_digest(
                    &self.binding,
                    &proof.member,
                    &proof.provider_certificate,
                )?,
                &proof.provider_signature,
            )?;
            let input = RosterCompactTerminalMemberSigningInputV2 {
                binding: self.binding.clone(),
                member: proof.member.clone(),
            };
            verify_digest_signature(
                &self.certificate.public_key,
                input.digest()?,
                &proof.signature,
            )?;
        }
        Ok(())
    }

    pub(crate) fn verify_raw_terminal(
        &self,
        admission: &Admission,
        terminal: &TerminalRecord,
    ) -> Result<(), RosterAttestationError> {
        terminal
            .validate_for(admission)
            .map_err(|_| RosterAttestationError)?;
        if self.binding.profile != admission.profile()
            || self.binding.roster_id != *admission.roster_id().as_bytes()
            || self.binding.admission_commitment != admission.body_commitment()
            || self.binding.terminal_body_commitment != terminal.body_commitment()
            || self.binding.terminal_phase_tag
                != terminal.phase().map_err(|_| RosterAttestationError)?.tag()
            || self.binding.terminal_checkpoint
                != compact_field(
                    COMPACT_ADMISSION_FIELD_CHECKPOINT,
                    admission.terminal_checkpoint(),
                )
            || self.binding.terminal_result
                != compact_field(COMPACT_ADMISSION_FIELD_RESULT, admission.terminal_result())
            || self.proofs.len() != admission.members().len()
            || terminal.proof_commitments().len() != self.proofs.len()
        {
            return Err(RosterAttestationError);
        }
        for ((member, proof), stable) in admission
            .members()
            .iter()
            .zip(&self.proofs)
            .zip(terminal.proof_commitments())
        {
            if proof.member.member_operation_id != *member.operation_id().as_bytes()
                || proof.member.descriptor_length as usize != member.descriptor().len()
                || proof.member.descriptor_commitment != member.descriptor_commitment()
                || proof.member.expected_member_version != member.expected_version()
                || proof.member.admission_generation != admission.expected_generation().get()
                || proof.member.stable_proof_commitment != *stable
            {
                return Err(RosterAttestationError);
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RosterCompactTerminalEvidenceV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            certificate: RosterAttestationLeafCertificateV1,
            binding: RosterCompactTerminalEvidenceBindingV2,
            proofs: BoundedVec<RosterCompactTerminalMemberProofV2, MAX_MEMBERS>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            certificate: wire.certificate,
            binding: wire.binding,
            proofs: wire.proofs.0,
        };
        value
            .validate_structure()
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl fmt::Debug for RosterCompactTerminalEvidenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterCompactTerminalEvidenceV2(<redacted>)")
    }
}

/// Crate-private compact verification inputs. This verification has no raw
/// descriptor or provider-evidence dependency and is suitable for followers,
/// snapshots, and deterministic post-terminal compaction.
pub(crate) struct CompactTerminalEvidenceVerificationV2<'a> {
    pub(crate) root: &'a RosterAttestationTrustRootV1,
    pub(crate) configuration_identity: SessionConsensusIdentity,
    pub(crate) logical_time: Timestamp,
    pub(crate) binding: RequestBindingKey,
    pub(crate) registration: BackendRegistration,
    pub(crate) admission_provenance: &'a RosterCompactAdmissionProvenanceV2,
    pub(crate) committing_authority: &'a AuthorityBinding,
    pub(crate) evidence: &'a RosterCompactTerminalEvidenceV2,
}

/// Verify terminal compact evidence without the original raw descriptor,
/// provider evidence, plan, checkpoint, or result bytes.
pub(crate) fn verify_compact_terminal_evidence_v2(
    verification: CompactTerminalEvidenceVerificationV2<'_>,
) -> Result<(), RosterAttestationError> {
    verification.evidence.verify_compact_for(
        verification.root,
        verification.configuration_identity,
        verification.logical_time,
        verification.binding,
        verification.registration,
        verification.admission_provenance,
        verification.committing_authority,
    )
}

fn compact_field(field: u8, bytes: &[u8]) -> RosterCompactFieldCommitmentV2 {
    RosterCompactFieldCommitmentV2 {
        length: bytes.len() as u32,
        commitment: compact_admission_field_commitment(field, bytes),
    }
}

fn compact_registration_matches(
    binding_bytes: [u8; 120],
    evidence: &RosterCompactTerminalEvidenceBindingV2,
) -> Result<(), RosterAttestationError> {
    let binding =
        RequestBindingKey::from_bytes(binding_bytes).map_err(|_| RosterAttestationError)?;
    let mut expected_request_id = [0; 56];
    expected_request_id[..8].copy_from_slice(&binding.history_epoch().to_be_bytes());
    expected_request_id[8..24].copy_from_slice(binding.roster_id.as_bytes());
    expected_request_id[24..].copy_from_slice(&evidence.admission_commitment);
    if evidence.registration_request_id != expected_request_id
        || evidence.registration_terminal_slot != command_id(TERMINAL_SLOT_DOMAIN, binding)
    {
        return Err(RosterAttestationError);
    }
    Ok(())
}

fn verify_compact_terminal_chain(
    evidence: &RosterCompactTerminalEvidenceBindingV2,
    proofs: &[RosterCompactTerminalMemberProofV2],
    binding: RequestBindingKey,
    registration: BackendRegistration,
    admission_provenance: &RosterCompactAdmissionProvenanceV2,
) -> Result<(), RosterAttestationError> {
    let provenance = admission_provenance.input();
    let (handle, request_id, terminal_slot) = registration.consensus_parts();
    if provenance.scope != binding.scope.digest()
        || provenance.tenant_scope_partition != binding.tenant_scope_partition
        || provenance.session_key_commitment != binding.session_key_commitment
        || provenance.roster_id != *binding.roster_id.as_bytes()
        || provenance.profile != evidence.profile
        || provenance.configuration_identity != evidence.configuration_identity
        || provenance.roster_id != evidence.roster_id
        || provenance.admission_commitment != evidence.admission_commitment
        || provenance.authority_scope != evidence.authority_scope
        || provenance.authority_key_commitment != evidence.authority_key_commitment
        || evidence.terminal_checkpoint != provenance.protected_checkpoint
        || evidence.terminal_result != provenance.protected_result
        || evidence.registration_handle != handle
        || evidence.registration_request_id != request_id.to_bytes()
        || evidence.registration_terminal_slot != *terminal_slot.as_bytes()
        || proofs.len() != provenance.members.len()
    {
        return Err(RosterAttestationError);
    }
    for (member, admission_member) in proofs.iter().zip(&provenance.members) {
        if member.member.ordinal != admission_member.ordinal
            || member.member.member_operation_id != admission_member.member_operation_id
            || member.member.descriptor_length != admission_member.descriptor_length
            || member.member.descriptor_commitment != admission_member.descriptor_commitment
            || member.member.expected_member_version != admission_member.expected_member_version
            || member.member.admission_generation != provenance.expected_generation
        {
            return Err(RosterAttestationError);
        }
    }
    Ok(())
}

fn update_compact_terminal_binding(
    hasher: &mut Sha256,
    binding: &RosterCompactTerminalEvidenceBindingV2,
) {
    hasher.update(binding.profile.schema().to_be_bytes());
    hasher.update(binding.profile.consumer_revision().to_be_bytes());
    hasher.update(binding.profile.digest());
    update_consensus_identity_attestation(hasher, binding.configuration_identity);
    hasher.update(binding.certificate_subject_identity_commitment);
    hasher.update([binding.certificate_role.tag()]);
    hasher.update(binding.admission_provenance_commitment);
    hasher.update(binding.binding);
    hasher.update(binding.registration_handle);
    hasher.update(binding.registration_request_id);
    hasher.update(binding.registration_terminal_slot);
    hasher.update(binding.roster_id);
    hasher.update(binding.admission_commitment);
    hasher.update([binding.terminal_phase_tag]);
    hasher.update(binding.terminal_body_commitment);
    for field in [binding.terminal_checkpoint, binding.terminal_result] {
        hasher.update(field.length.to_be_bytes());
        hasher.update(field.commitment);
    }
    hasher.update(binding.authority_scope);
    hasher.update(binding.authority_key_commitment);
    hasher.update(binding.authority_owner_commitment);
    hasher.update(binding.authority_fence.to_be_bytes());
    hasher.update(binding.authority_credential_id.to_be_bytes());
    hasher.update(binding.authority_generation.to_be_bytes());
    update_timestamp_attestation(hasher, binding.authority_acquired_at);
    update_timestamp_attestation(hasher, binding.authority_expires_at);
}

fn update_compact_terminal_member(
    hasher: &mut Sha256,
    member: &RosterCompactTerminalMemberProjectionV2,
) {
    hasher.update([member.ordinal]);
    hasher.update(member.member_operation_id);
    hasher.update(member.descriptor_length.to_be_bytes());
    hasher.update(member.descriptor_commitment);
    hasher.update(member.expected_member_version.to_be_bytes());
    hasher.update(member.admission_generation.to_be_bytes());
    hasher.update(member.proof_epoch.to_be_bytes());
    hasher.update([member.provider_operation.tag(), member.outcome.tag()]);
    hasher.update(member.evidence_length.to_be_bytes());
    hasher.update(member.evidence_commitment);
    hasher.update(member.stable_proof_commitment);
}

/// Reconstruct the Provider receipt digest from durable compact evidence.
/// Unlike executor aggregation, the provider receipt has no terminal phase,
/// terminal body, raw descriptor, raw evidence, certificate rotation, or
/// signature material in its signed body. The descriptor/evidence commitments
/// are sufficient to preserve the original raw bindings after compaction.
pub(crate) fn provider_receipt_compact_digest(
    binding: &RosterCompactTerminalEvidenceBindingV2,
    member: &RosterCompactTerminalMemberProjectionV2,
    certificate: &RosterAttestationLeafCertificateV1,
) -> Result<[u8; 32], RosterAttestationError> {
    binding.validate()?;
    let phase = Phase::from_tag(binding.terminal_phase_tag).map_err(|_| RosterAttestationError)?;
    member.validate(member.ordinal as usize, phase)?;
    certificate.validate_structure()?;
    if certificate.role()? != RosterAttestationCertificateRoleV1::Provider
        || certificate.configuration_identity != binding.configuration_identity
        || certificate.scope != binding.authority_scope
    {
        return Err(RosterAttestationError);
    }
    // Byte-for-byte the fixed portion of
    // `RosterProviderReceiptSigningInputV1::challenge_digest()`, expressed
    // from retained compact commitments. This preserves the Provider
    // signature across raw-to-compact conversion.
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_ATTESTATION_PROVIDER_RECEIPT_DOMAIN);
    hasher.update(ROSTER_ATTESTATION_PROVIDER_RECEIPT_MAGIC);
    hasher.update([2]);
    hasher.update(binding.profile.schema().to_be_bytes());
    hasher.update(binding.profile.consumer_revision().to_be_bytes());
    hasher.update(binding.profile.digest());
    update_consensus_identity_attestation(&mut hasher, binding.configuration_identity);
    hasher.update(binding.binding);
    hasher.update(binding.registration_handle);
    hasher.update(binding.registration_request_id);
    hasher.update(binding.registration_terminal_slot);
    hasher.update(binding.roster_id);
    hasher.update(binding.admission_commitment);
    hasher.update([member.ordinal]);
    hasher.update(member.member_operation_id);
    hasher.update((member.descriptor_length as u64).to_be_bytes());
    hasher.update(member.descriptor_commitment);
    hasher.update(member.expected_member_version.to_be_bytes());
    hasher.update(member.admission_generation.to_be_bytes());
    hasher.update(binding.authority_scope);
    hasher.update(binding.authority_key_commitment);
    hasher.update(binding.authority_owner_commitment);
    hasher.update(binding.authority_fence.to_be_bytes());
    hasher.update(binding.authority_credential_id.to_be_bytes());
    hasher.update(binding.authority_generation.to_be_bytes());
    update_timestamp_attestation(&mut hasher, binding.authority_acquired_at);
    update_timestamp_attestation(&mut hasher, binding.authority_expires_at);
    hasher.update(member.proof_epoch.to_be_bytes());
    hasher.update([member.provider_operation.tag()]);
    provider_receipt_digest_from_challenge_commitment_v1(
        hasher.finalize().into(),
        certificate.subject_identity_commitment,
        member.proof_epoch,
        member.provider_operation,
        member.outcome,
        member.evidence_length as usize,
        member.evidence_commitment,
    )
}

/// Crate-private inputs for deterministic executor-proof verification.
pub(crate) struct ExecutorTerminalProofVerification<'a> {
    pub(crate) root: Option<&'a RosterAttestationTrustRootV1>,
    pub(crate) configuration_identity: SessionConsensusIdentity,
    pub(crate) logical_time: Timestamp,
    pub(crate) binding: RequestBindingKey,
    pub(crate) registration: BackendRegistration,
    pub(crate) admission: &'a Admission,
    pub(crate) authority: &'a AuthorityBinding,
    pub(crate) terminal: &'a TerminalRecord,
    pub(crate) bundle: &'a RosterExecutorProofBundleV1,
}

struct TerminalProofSigningInput<'a> {
    certificate: &'a RosterAttestationLeafCertificateV1,
    configuration_identity: SessionConsensusIdentity,
    binding: RequestBindingKey,
    registration: BackendRegistration,
    admission: &'a Admission,
    authority: &'a AuthorityBinding,
    terminal: &'a TerminalRecord,
    member: &'a Member,
    proof: &'a RosterExecutorMemberProofV1,
}

/// Reconstruct and verify every signed executor proof before a terminal row
/// or business session row can change. All time comparisons use the caller's
/// replicated logical time; this function has no wall-clock, network, KMS, or
/// local-file dependency.
pub(crate) fn verify_executor_terminal_proof_bundle(
    verification: ExecutorTerminalProofVerification<'_>,
) -> Result<(), RosterAttestationError> {
    let ExecutorTerminalProofVerification {
        root,
        configuration_identity,
        logical_time,
        binding,
        registration,
        admission,
        authority,
        terminal,
        bundle,
    } = verification;
    let root = root.ok_or(RosterAttestationError)?;
    bundle.validate_structure()?;
    terminal
        .validate_for(admission)
        .map_err(|_| RosterAttestationError)?;
    binding.validate().map_err(|_| RosterAttestationError)?;
    validate_attestation_registration(binding, registration, admission)?;
    if binding.scope != admission.scope()
        || binding.roster_id != admission.roster_id()
        || authority.scope() != admission.scope()
        || authority.key() != admission.key()
        || authority.generation() != admission.expected_generation()
        || authority.fence().get() == 0
        || authority.credential_id() == 0
        || authority.expires_at() <= authority.acquired_at()
        || logical_time < authority.acquired_at()
        || logical_time >= authority.expires_at()
    {
        return Err(RosterAttestationError);
    }
    let certificate = &bundle.certificate;
    certificate.verify_root(root)?;
    if RosterAttestationCertificateRoleV1::from_tag(certificate.role_tag)?
        != RosterAttestationCertificateRoleV1::Executor
        || certificate.configuration_identity != configuration_identity
        || certificate.scope != admission.scope().digest()
        || logical_time < certificate.not_before
        || logical_time >= certificate.not_after
        || bundle.proofs.len() != admission.members().len()
        || terminal.proof_commitments().len() != admission.members().len()
    {
        return Err(RosterAttestationError);
    }

    for (index, (member, proof)) in admission.members().iter().zip(&bundle.proofs).enumerate() {
        if proof.ordinal != index as u8 || member.ordinal() != index as u8 {
            return Err(RosterAttestationError);
        }
        let operation = proof.operation()?;
        let outcome = proof.outcome()?;
        if !attested_provider_outcome_allowed(operation, outcome)
            || outcome.phase() != terminal.phase().map_err(|_| RosterAttestationError)?
        {
            return Err(RosterAttestationError);
        }
        verify_provider_receipt(
            root,
            configuration_identity,
            logical_time,
            binding,
            registration,
            admission,
            authority,
            member,
            proof,
        )?;
        let digest = terminal_proof_signing_digest(TerminalProofSigningInput {
            certificate,
            configuration_identity,
            binding,
            registration,
            admission,
            authority,
            terminal,
            member,
            proof,
        })?;
        verify_digest_signature(&certificate.public_key, digest, &proof.signature)?;
        let commitment = stable_terminal_proof_commitment(
            binding,
            registration,
            admission,
            terminal.phase().map_err(|_| RosterAttestationError)?,
            member,
            outcome,
            proof.evidence_commitment(),
        )?;
        if terminal.proof_commitments().get(index).copied() != Some(commitment) {
            return Err(RosterAttestationError);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_provider_receipt(
    root: &RosterAttestationTrustRootV1,
    configuration_identity: SessionConsensusIdentity,
    logical_time: Timestamp,
    binding: RequestBindingKey,
    registration: BackendRegistration,
    admission: &Admission,
    authority: &AuthorityBinding,
    member: &Member,
    proof: &RosterExecutorMemberProofV1,
) -> Result<(), RosterAttestationError> {
    let certificate = &proof.provider_certificate;
    certificate.verify_root(root)?;
    if certificate.role()? != RosterAttestationCertificateRoleV1::Provider
        || certificate.configuration_identity != configuration_identity
        || certificate.scope != admission.scope().digest()
        || logical_time < certificate.not_before
        || logical_time >= certificate.not_after
    {
        return Err(RosterAttestationError);
    }
    let digest = provider_receipt_signing_digest(
        certificate,
        configuration_identity,
        binding,
        registration,
        admission,
        authority,
        member,
        proof,
    )?;
    verify_digest_signature(&certificate.public_key, digest, &proof.provider_signature)
}

/// Stable terminal contribution for one member proof.
///
/// Unlike the leaf signature this deliberately excludes the replaceable
/// current authority, proof epoch, certificate, and signature. A valid
/// higher-fence successor can therefore reproduce the exact immutable
/// terminal record while still presenting a newly issued, current proof
/// bundle to the state machine.
pub(crate) fn stable_terminal_proof_commitment(
    binding: RequestBindingKey,
    registration: BackendRegistration,
    admission: &Admission,
    phase: Phase,
    member: &Member,
    outcome: RosterProviderOutcomeV1,
    evidence_commitment: [u8; 32],
) -> Result<[u8; 32], RosterAttestationError> {
    binding.validate().map_err(|_| RosterAttestationError)?;
    validate_attestation_registration(binding, registration, admission)?;
    let (_, request_id, terminal_slot) = registration.consensus_parts();
    if evidence_commitment == [0; 32] {
        return Err(RosterAttestationError);
    }
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_ATTESTATION_STABLE_PROOF_DOMAIN);
    hasher.update([1]);
    hasher.update(binding.to_bytes());
    hasher.update(request_id.to_bytes());
    hasher.update(terminal_slot.as_bytes());
    hasher.update(admission.roster_id().as_bytes());
    hasher.update(admission.body_commitment());
    hasher.update([phase.tag()]);
    hasher.update([member.ordinal()]);
    hasher.update(member.operation_id().as_bytes());
    hasher.update((member.descriptor().len() as u64).to_be_bytes());
    hasher.update(member.descriptor());
    hasher.update(member.descriptor_commitment());
    hasher.update(member.expected_version().to_be_bytes());
    hasher.update(admission.expected_generation().get().to_be_bytes());
    hasher.update([outcome.tag()]);
    hasher.update(evidence_commitment);
    Ok(hasher.finalize().into())
}

fn validate_attestation_registration(
    binding: RequestBindingKey,
    registration: BackendRegistration,
    admission: &Admission,
) -> Result<(), RosterAttestationError> {
    let (handle, request_id, terminal_slot) = registration.consensus_parts();
    if handle == [0; 32]
        || terminal_slot.as_bytes() == &[0; 32]
        || request_id
            != RequestId::bind(binding.history_epoch(), admission)
                .map_err(|_| RosterAttestationError)?
    {
        return Err(RosterAttestationError);
    }
    Ok(())
}

fn terminal_proof_signing_digest(
    input: TerminalProofSigningInput<'_>,
) -> Result<[u8; 32], RosterAttestationError> {
    let TerminalProofSigningInput {
        certificate,
        configuration_identity,
        binding,
        registration,
        admission,
        authority,
        terminal,
        member,
        proof,
    } = input;
    let operation = proof.operation()?;
    let outcome = proof.outcome()?;
    let (handle, request_id, terminal_slot) = registration.consensus_parts();
    if binding.scope != admission.scope()
        || binding.roster_id != admission.roster_id()
        || terminal.request_id() != request_id
        || proof.ordinal != member.ordinal()
    {
        return Err(RosterAttestationError);
    }
    let input = RosterTerminalAttestationSigningInputV1 {
        profile: admission.profile(),
        configuration_identity,
        certificate_subject_identity_commitment: certificate.subject_identity_commitment,
        certificate_role: RosterAttestationCertificateRoleV1::from_tag(certificate.role_tag)?,
        binding: binding.to_bytes(),
        registration_handle: handle,
        registration_request_id: request_id.to_bytes(),
        registration_terminal_slot: *terminal_slot.as_bytes(),
        roster_id: *admission.roster_id().as_bytes(),
        admission_commitment: admission.body_commitment(),
        terminal_phase: terminal.phase().map_err(|_| RosterAttestationError)?,
        terminal_body_commitment: terminal.body_commitment(),
        ordinal: member.ordinal(),
        member_operation_id: *member.operation_id().as_bytes(),
        descriptor: member.descriptor().to_vec(),
        descriptor_commitment: member.descriptor_commitment(),
        expected_member_version: member.expected_version(),
        admission_generation: admission.expected_generation().get(),
        authority_scope: authority.scope().digest(),
        authority_key_canonical: authority.key().canonical_digest_input(),
        authority_owner: authority.owner().as_str().as_bytes().to_vec(),
        authority_fence: authority.fence().get(),
        authority_credential_id: authority.credential_id(),
        authority_generation: authority.generation().get(),
        authority_acquired_at: authority.acquired_at(),
        authority_expires_at: authority.expires_at(),
        proof_epoch: proof.proof_epoch,
        provider_operation: operation,
        outcome,
        evidence: proof.evidence.clone(),
    };
    input.digest()
}

#[allow(clippy::too_many_arguments)]
fn provider_receipt_signing_digest(
    certificate: &RosterAttestationLeafCertificateV1,
    configuration_identity: SessionConsensusIdentity,
    binding: RequestBindingKey,
    registration: BackendRegistration,
    admission: &Admission,
    authority: &AuthorityBinding,
    member: &Member,
    proof: &RosterExecutorMemberProofV1,
) -> Result<[u8; 32], RosterAttestationError> {
    let operation = proof.operation()?;
    let outcome = proof.outcome()?;
    let (handle, request_id, terminal_slot) = registration.consensus_parts();
    if binding.scope != admission.scope()
        || binding.roster_id != admission.roster_id()
        || proof.ordinal != member.ordinal()
    {
        return Err(RosterAttestationError);
    }
    RosterProviderReceiptSigningInputV1 {
        profile: admission.profile(),
        configuration_identity,
        certificate_subject_identity_commitment: certificate.subject_identity_commitment,
        certificate_role: certificate.role()?,
        binding: binding.to_bytes(),
        registration_handle: handle,
        registration_request_id: request_id.to_bytes(),
        registration_terminal_slot: *terminal_slot.as_bytes(),
        roster_id: *admission.roster_id().as_bytes(),
        admission_commitment: admission.body_commitment(),
        ordinal: member.ordinal(),
        member_operation_id: *member.operation_id().as_bytes(),
        descriptor: member.descriptor().to_vec(),
        descriptor_commitment: member.descriptor_commitment(),
        expected_member_version: member.expected_version(),
        admission_generation: admission.expected_generation().get(),
        authority_scope: authority.scope().digest(),
        authority_key_canonical: authority.key().canonical_digest_input(),
        authority_owner: authority.owner().as_str().as_bytes().to_vec(),
        authority_fence: authority.fence().get(),
        authority_credential_id: authority.credential_id(),
        authority_generation: authority.generation().get(),
        authority_acquired_at: authority.acquired_at(),
        authority_expires_at: authority.expires_at(),
        proof_epoch: proof.proof_epoch,
        provider_operation: operation,
        outcome,
        evidence: proof.evidence.clone(),
    }
    .digest()
}

fn descriptor_commitment_from_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DOMAIN);
    update_len_prefixed(&mut hasher, bytes);
    hasher.finalize().into()
}

/// Compute the shared exact opaque-evidence commitment used by executor
/// issuance and deterministic consensus verification. Callers must enforce
/// the 1..=4096 byte proof bound separately before issuance.
#[doc(hidden)]
pub fn roster_executor_evidence_commitment(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROSTER_ATTESTATION_EVIDENCE_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

fn evidence_commitment_from_bytes(bytes: &[u8]) -> [u8; 32] {
    roster_executor_evidence_commitment(bytes)
}

fn attested_provider_outcome_allowed(
    operation: RosterProviderOperationV1,
    outcome: RosterProviderOutcomeV1,
) -> bool {
    match operation {
        // Execution can establish only its own positive terminal fact. In
        // particular a product provider cannot turn an execute failure into a
        // NotApplied/Reconciled assertion without the dedicated reconciliation
        // operation and Provider receipt.
        RosterProviderOperationV1::Execute => outcome == RosterProviderOutcomeV1::AppliedExecuted,
        RosterProviderOperationV1::Status => matches!(
            outcome,
            RosterProviderOutcomeV1::AppliedExecuted | RosterProviderOutcomeV1::AppliedAdopted
        ),
        RosterProviderOperationV1::Adopt => outcome == RosterProviderOutcomeV1::AppliedAdopted,
        // Only Reconcile may make a negative or compensation conclusion.
        RosterProviderOperationV1::Reconcile => matches!(
            outcome,
            RosterProviderOutcomeV1::NotAppliedReconciled
                | RosterProviderOutcomeV1::CompensatedReconciled
        ),
        RosterProviderOperationV1::Compensate => false,
        // Preparation is intentionally not a terminal observation. It may
        // establish a local retry state, never a conclusive remote outcome.
        RosterProviderOperationV1::Prepare => false,
    }
}

fn update_consensus_identity_attestation(hasher: &mut Sha256, identity: SessionConsensusIdentity) {
    update_len_prefixed(hasher, identity.cluster_id().as_bytes());
    hasher.update(identity.configuration_id().as_bytes());
    hasher.update(identity.configuration_epoch().get().to_be_bytes());
}

fn update_timestamp_attestation(hasher: &mut Sha256, timestamp: Timestamp) {
    hasher.update(
        timestamp
            .as_offset_datetime()
            .unix_timestamp_nanos()
            .to_be_bytes(),
    );
}

fn canonical_verifying_key(
    bytes: &[u8; ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES],
) -> Result<VerifyingKey, RosterAttestationError> {
    if !matches!(bytes[0], 0x02 | 0x03) {
        return Err(RosterAttestationError);
    }
    let key = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| RosterAttestationError)?;
    if key.to_sec1_point(true).as_bytes() != bytes {
        return Err(RosterAttestationError);
    }
    Ok(key)
}

fn canonical_signature(
    bytes: &[u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
) -> Result<Signature, RosterAttestationError> {
    let signature = Signature::from_slice(bytes).map_err(|_| RosterAttestationError)?;
    // A changed normalized value identifies a high-S encoding. Accepting the
    // replacement would make one mathematical signature have two command
    // encodings.
    if signature.normalize_s() != signature {
        return Err(RosterAttestationError);
    }
    Ok(signature)
}

fn verify_digest_signature(
    public_key: &[u8; ROSTER_ATTESTATION_P256_COMPRESSED_PUBLIC_KEY_BYTES],
    digest: [u8; 32],
    signature: &[u8; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
) -> Result<(), RosterAttestationError> {
    let key = canonical_verifying_key(public_key)?;
    let signature = canonical_signature(signature)?;
    key.verify_prehash(&digest, &signature)
        .map_err(|_| RosterAttestationError)
}
/// Monotonic V2 epoch floor whose advance makes older bindings irreversible.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct IrreversibleHistoryFloor {
    scope: Scope,
    tenant_scope_partition: [u8; 32],
    retired_through: u64,
}

impl IrreversibleHistoryFloor {
    /// Start the durable floor for the exact authenticated tenant/scope
    /// partition represented by `binding`.
    ///
    /// The tenant is retained only as a domain-separated commitment. A floor
    /// can therefore neither reveal a tenant identity nor authorize history
    /// operations for another tenant that happens to share the same scope.
    pub(crate) fn initial(binding: RequestBindingKey) -> Result<Self, Error> {
        binding.validate()?;
        Ok(Self {
            scope: binding.scope,
            tenant_scope_partition: binding.tenant_scope_partition,
            retired_through: 0,
        })
    }

    /// Return the greatest history epoch irreversibly retired by this floor.
    pub(crate) const fn retired_through(self) -> u64 {
        self.retired_through
    }

    /// Validate an exact binding before a new admission reserves capacity.
    ///
    /// Both its authenticated tenant/scope partition and its epoch are
    /// checked. A scalar epoch supplied without the binding is deliberately
    /// insufficient because it could act as a cross-tenant existence oracle.
    pub(crate) fn validate_new_binding(self, binding: RequestBindingKey) -> Result<(), Error> {
        self.validate()?;
        binding.validate()?;
        if binding.scope != self.scope
            || binding.tenant_scope_partition != self.tenant_scope_partition
        {
            return Err(Error::InvalidAuthority);
        }
        if binding.history_epoch() <= self.retired_through {
            Err(Error::InvalidHistory)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn advance_to(self, retired_through: u64) -> Result<Self, Error> {
        validate_history_epoch(retired_through)?;
        let next = Self {
            scope: self.scope,
            tenant_scope_partition: self.tenant_scope_partition,
            retired_through,
        };
        next.strictly_advances(self)?;
        Ok(next)
    }

    /// Verify that this floor is a strict monotonic advance of the same scope.
    pub(crate) fn strictly_advances(self, previous: Self) -> Result<(), Error> {
        self.validate()?;
        previous.validate()?;
        if self.scope != previous.scope
            || self.tenant_scope_partition != previous.tenant_scope_partition
        {
            return Err(Error::InvalidAuthority);
        }
        if self.retired_through <= previous.retired_through {
            return Err(Error::InvalidHistory);
        }
        Ok(())
    }

    /// Encode this durable scope-bound retirement floor in its canonical frame.
    pub(crate) fn to_canonical_bytes(self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        encode_frame(
            HISTORY_FLOOR_FRAME_MAGIC,
            HISTORY_FLOOR_FRAME_DOMAIN,
            &(
                self.scope.digest(),
                self.tenant_scope_partition,
                self.retired_through,
            ),
            MAX_HISTORY_FLOOR_CODEC_BYTES,
        )
    }

    /// Decode and validate one exact canonical durable retirement floor frame.
    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (scope, tenant_scope_partition, retired_through): ([u8; 32], [u8; 32], u64) =
            decode_frame(
                bytes,
                HISTORY_FLOOR_FRAME_MAGIC,
                HISTORY_FLOOR_FRAME_DOMAIN,
                MAX_HISTORY_FLOOR_CODEC_BYTES,
            )?;
        let value = Self {
            scope: Scope::from_digest(scope),
            tenant_scope_partition,
            retired_through,
        };
        value.validate()?;
        if value.to_canonical_bytes()?.as_slice() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(value)
    }

    /// Verify that one exact binding is covered by this same-scope durable
    /// retirement floor.
    ///
    /// Storage adapters use this check in the transaction that advances the
    /// floor, deletes the matching tombstone, and releases its global charge.
    /// Accepting only the opaque binding prevents a caller from presenting an
    /// unrelated epoch while hiding a cross-scope retirement.
    #[cfg(test)]
    pub(crate) fn permits_binding(self, binding: RequestBindingKey) -> Result<(), Error> {
        self.validate()?;
        binding.validate()?;
        if binding.scope != self.scope
            || binding.tenant_scope_partition != self.tenant_scope_partition
        {
            return Err(Error::InvalidAuthority);
        }
        if binding.history_epoch() > self.retired_through {
            return Err(Error::InvalidHistory);
        }
        Ok(())
    }

    fn validate(self) -> Result<(), Error> {
        self.scope.validate()?;
        if self.tenant_scope_partition == [0; 32] || self.retired_through > MAX_HISTORY_EPOCH {
            return Err(Error::InvalidHistory);
        }
        Ok(())
    }
}

impl fmt::Debug for IrreversibleHistoryFloor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IrreversibleHistoryFloor(<redacted>)")
    }
}

/// Compact conflict binding retained after the exact terminal payload ages out.
///
/// This tombstone is retired only with the enclosing V2 history epoch. Age
/// alone therefore never reopens a stable roster ID for a different body.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TerminalConflictTombstone {
    binding_key: RequestBindingKey,
    admission_body_commitment: [u8; 32],
    terminal_body_commitment: [u8; 32],
    admission_owner: OwnerId,
    admission_fence: u64,
    expected_generation: u64,
    phase_tag: u8,
}

/// Complete caller claim for one compacted terminal lookup.
///
/// The immutable admission provenance and replaceable current authority are
/// intentionally grouped so a recovery path cannot accidentally validate a
/// mix of values from distinct lookups or leases.
pub(crate) struct CompactedTerminalLookup<'a> {
    /// Retained-history epoch bound into the original admission request ID.
    pub(crate) history_epoch: u64,
    /// Exact least-authority scope claimed by the caller.
    pub(crate) scope: Scope,
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
    /// Construct the validated compact binding for an exact terminal record.
    pub(crate) fn new(admission: &Admission, record: &TerminalRecord) -> Result<Self, Error> {
        record.validate_for(admission)?;
        let value = Self {
            binding_key: admission.binding_key(record.request_id().history_epoch())?,
            admission_body_commitment: admission.body_commitment(),
            terminal_body_commitment: record.body_commitment(),
            admission_owner: admission.logical_owner().clone(),
            admission_fence: admission.admission_fence().get(),
            expected_generation: admission.expected_generation().get(),
            phase_tag: record.phase()?.tag(),
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
        if self.binding_key != binding_key {
            return Err(Error::InvalidAuthority);
        }
        if self.admission_body_commitment != admission.body_commitment() {
            return Err(Error::RequestConflict);
        }
        if self.admission_owner != *admission.logical_owner()
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

    /// Validate an exact terminal retry after full payload compaction.
    ///
    /// The admission bytes no longer exist, so reconstruct only the immutable
    /// request identity that they committed. Current execution authority is a
    /// replaceable guard: it must be a valid strictly higher fence for the
    /// same generation, while the terminal body and slot remain byte-exact.
    pub(crate) fn validate_compacted_terminal(
        &self,
        binding: RequestBindingKey,
        request_id: RequestId,
        terminal_slot: [u8; 32],
        current_fence: FenceToken,
        current_generation: Generation,
        terminal_body_commitment: [u8; 32],
    ) -> Result<CompactedTerminalStatus, Error> {
        self.validate()?;
        if self.binding_key != binding {
            return Err(Error::InvalidAuthority);
        }
        if current_fence.get() <= self.admission_fence
            || current_generation.get() != self.expected_generation
        {
            return Err(Error::InvalidAuthority);
        }
        let expected_request_id = RequestId {
            history_epoch: self.binding_key.history_epoch,
            roster_id: self.binding_key.roster_id,
            body_commitment: self.admission_body_commitment,
        };
        let expected_terminal_slot = command_id(TERMINAL_SLOT_DOMAIN, self.binding_key);
        if request_id != expected_request_id
            || terminal_slot != expected_terminal_slot
            || terminal_body_commitment != self.terminal_body_commitment
        {
            return Err(Error::RequestConflict);
        }
        Ok(CompactedTerminalStatus {
            phase: Phase::from_tag(self.phase_tag)?,
            terminal_body_commitment: self.terminal_body_commitment,
        })
    }

    /// Validate a compacted replay lookup without retaining an admission body.
    pub(crate) fn validate_lookup(
        &self,
        lookup: CompactedTerminalLookup<'_>,
    ) -> Result<CompactedTerminalStatus, Error> {
        let binding_key = request_binding_key(
            lookup.history_epoch,
            lookup.scope,
            lookup.key,
            lookup.roster_id,
        )?;
        if self.binding_key != binding_key {
            return Err(Error::InvalidAuthority);
        }
        if self.admission_owner != *lookup.original_owner
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

    pub(crate) const fn binding_key(&self) -> RequestBindingKey {
        self.binding_key
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
        self.binding_key.validate()?;
        if self.admission_body_commitment == [0; 32] || self.terminal_body_commitment == [0; 32] {
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
    binding_key: RequestBindingKey,
    admission_body_commitment: [u8; 32],
    terminal_body_commitment: [u8; 32],
    admission_owner: OwnerId,
    admission_fence: u64,
    expected_generation: u64,
    phase_tag: u8,
}

impl<'de> Deserialize<'de> for TerminalConflictTombstone {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = TerminalConflictTombstoneWire::deserialize(deserializer)?;
        let value = Self {
            binding_key: wire.binding_key,
            admission_body_commitment: wire.admission_body_commitment,
            terminal_body_commitment: wire.terminal_body_commitment,
            admission_owner: wire.admission_owner,
            admission_fence: wire.admission_fence,
            expected_generation: wire.expected_generation,
            phase_tag: wire.phase_tag,
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
mod tests {
    use super::*;
    use crate::{SessionKeyType, StableId, SESSION_KEY_TYPE_MAX_BYTES};
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};

    fn roster_attestation_trust_root(
        root_id: [u8; 32],
        scalar: u8,
    ) -> RosterAttestationTrustRootV1 {
        let signing_key =
            SigningKey::from_bytes((&[scalar; 32]).into()).expect("fixed P-256 roster root scalar");
        let public_key = signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed P-256 public key width");
        RosterAttestationTrustRootV1::new(root_id, public_key)
            .expect("valid fixed P-256 roster trust root")
    }

    #[test]
    fn roster_attestation_root_identity_binds_root_id_and_public_key() {
        let root = roster_attestation_trust_root([0x11; 32], 0x21);
        let cloned_root = root.clone();
        let same_id_different_key = roster_attestation_trust_root([0x11; 32], 0x22);
        let different_id_same_key = roster_attestation_trust_root([0x12; 32], 0x21);

        assert_eq!(root.identity(), cloned_root.identity());
        assert_ne!(root.identity(), same_id_different_key.identity());
        assert_ne!(root.identity(), different_id_same_key.identity());
        assert_eq!(
            format!("{:?}", root.identity()),
            "RosterAttestationTrustRootIdentityV1(<redacted>)"
        );
    }

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"key")).unwrap(),
        }
    }
    fn maximum_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::new("t".repeat(128)).unwrap(),
            nf_kind: NetworkFunctionKind::new("n".repeat(64)).unwrap(),
            key_type: SessionKeyType::other("k".repeat(SESSION_KEY_TYPE_MAX_BYTES)).unwrap(),
            stable_id: StableId::new(Bytes::from(vec![0xab; StableId::MAX_BYTES])).unwrap(),
        }
    }
    fn maximum_owner() -> OwnerId {
        OwnerId::new("o".repeat(OwnerId::MAX_BYTES)).unwrap()
    }
    fn frame_sha256(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn compact_time(seconds: i64) -> Timestamp {
        let base: Timestamp = "2024-01-01T00:00:00Z".parse().expect("timestamp");
        base.add_seconds(seconds).expect("timestamp offset")
    }

    fn compact_identity() -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            crate::consensus::SessionConsensusClusterId::new("compact-roster")
                .expect("cluster identity"),
            crate::consensus::SessionConsensusConfigurationId::from_bytes([0x44; 32]),
            crate::consensus::SessionConsensusConfigurationEpoch::new(3)
                .expect("configuration epoch"),
        )
    }

    fn compressed_key(key: &p256::ecdsa::VerifyingKey) -> [u8; 33] {
        key.to_sec1_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed key")
    }

    fn sign_digest(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
        let signature: Signature = key.sign_prehash(&digest).expect("prehash signature");
        signature.normalize_s().to_bytes().into()
    }

    fn compact_certificate(
        root: &RosterAttestationTrustRootV1,
        root_key: &SigningKey,
        leaf_key: &SigningKey,
        role: RosterAttestationCertificateRoleV1,
        identity: SessionConsensusIdentity,
        scope: [u8; 32],
        subject: [u8; 32],
    ) -> RosterAttestationLeafCertificatePartsV1 {
        let mut parts = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role,
            configuration_identity: identity,
            scope,
            subject_identity_commitment: subject,
            leaf_epoch: 9,
            key_id: [0x91; 32],
            not_before: compact_time(1),
            not_after: compact_time(100),
            public_key: compressed_key(leaf_key.verifying_key()),
            root_signature: [0; 64],
        };
        parts.root_signature = sign_digest(
            root_key,
            RosterAttestationLeafCertificateV1::signing_digest(&parts)
                .expect("certificate preimage"),
        );
        parts
    }

    #[allow(clippy::type_complexity)]
    fn compact_v2_fixture(
        width: usize,
    ) -> (
        RosterAttestationTrustRootV1,
        SessionConsensusIdentity,
        Admission,
        RequestBindingKey,
        AuthorityBinding,
        BackendRegistration,
        RosterIngressAttestationSigningInputV1,
        RosterCompactAdmissionProvenanceV2,
        TerminalRecord,
        RosterCompactTerminalEvidenceV2,
    ) {
        compact_v2_fixture_with_maximum_projection(width, false)
    }

    #[allow(clippy::type_complexity)]
    fn compact_v2_fixture_with_maximum_projection(
        width: usize,
        maximum_projection: bool,
    ) -> (
        RosterAttestationTrustRootV1,
        SessionConsensusIdentity,
        Admission,
        RequestBindingKey,
        AuthorityBinding,
        BackendRegistration,
        RosterIngressAttestationSigningInputV1,
        RosterCompactAdmissionProvenanceV2,
        TerminalRecord,
        RosterCompactTerminalEvidenceV2,
    ) {
        use crate::fenced_mutation_roster_executor::AuthorityLeaseMetadata;

        let root_key = SigningKey::from_bytes((&[0x41; 32]).into()).expect("root signing key");
        let root =
            RosterAttestationTrustRootV1::new([0x42; 32], compressed_key(root_key.verifying_key()))
                .expect("root");
        let ingress_leaf = SigningKey::from_bytes((&[0x43; 32]).into()).expect("ingress leaf");
        let executor_leaf = SigningKey::from_bytes((&[0x45; 32]).into()).expect("executor leaf");
        let identity = compact_identity();
        let admission = Admission::authenticate(
            if maximum_projection {
                AdmissionProposal::new(
                    Profile::v1(),
                    RosterId::from_bytes([7; ROSTER_ID_BYTES]).expect("roster ID"),
                    (0..width)
                        .map(|ordinal| {
                            Member::new(
                                ordinal as u8,
                                MemberOperationId::from_bytes(
                                    [ordinal as u8 + 1; MEMBER_OPERATION_ID_BYTES],
                                )
                                .expect("member operation ID"),
                                vec![ordinal as u8 + 1; MAX_DESCRIPTOR_BYTES],
                                u64::MAX,
                            )
                            .expect("maximum member")
                        })
                        .collect(),
                    EstablishedMutation::put_checkpoint(
                        StateType::new("s".repeat(StateType::MAX_BYTES))
                            .expect("maximum state type"),
                    ),
                    vec![0xa5; MAX_PLAN_BYTES],
                    vec![0x3c; MAX_CHECKPOINT_BYTES],
                    vec![0x5a; MAX_RESULT_BYTES],
                )
                .expect("maximum proposal")
            } else {
                proposal(width).expect("proposal")
            },
            if maximum_projection {
                maximum_key()
            } else {
                key()
            },
            Scope::from_digest([0x46; 32]),
            if maximum_projection {
                maximum_owner()
            } else {
                OwnerId::new("compact-owner").expect("owner")
            },
            FenceToken::new(if maximum_projection { u64::MAX } else { 7 }),
            Generation::new(if maximum_projection { u64::MAX - 1 } else { 11 }),
        )
        .expect("admission");
        let authority = AuthorityBinding::for_admission(
            &admission,
            admission.logical_owner().clone(),
            admission.admission_fence(),
            AuthorityLeaseMetadata::new(
                13,
                admission.expected_generation(),
                compact_time(2),
                compact_time(90),
            ),
        )
        .expect("original authority");
        let binding = admission.binding_key(17).expect("post-apply binding");
        let ingress = RosterIngressAttestationSigningInputV1 {
            peer_identity_commitment: [0x47; 32],
            consumer_scope: admission.scope().digest(),
            request_id: [0x48; 16],
            operation_tag: 7,
            canonical_capsule_digest: [0x49; 32],
            authenticated_at: compact_time(10),
            peer_certificate_expires_at: compact_time(80),
            material_generation: 2,
            handshake_epoch: 3,
        };
        let ingress_subject = [0x4a; 32];
        let admission_input = RosterCompactAdmissionProvenanceSigningInputV2::for_admission(
            identity,
            &admission,
            &authority,
            &ingress,
            ingress_subject,
        )
        .expect("compact admission input");
        let ingress_certificate = compact_certificate(
            &root,
            &root_key,
            &ingress_leaf,
            RosterAttestationCertificateRoleV1::TransportIngress,
            identity,
            admission.scope().digest(),
            ingress_subject,
        );
        let provenance = RosterCompactAdmissionProvenanceV2::issue_from_signed_parts(
            &root,
            ingress_certificate,
            &admission_input,
            sign_digest(
                &ingress_leaf,
                admission_input.digest().expect("admission digest"),
            ),
        )
        .expect("compact admission provenance");
        let request_id = RequestId::bind(binding.history_epoch(), &admission).expect("request id");
        let registration =
            BackendRegistration::issue([0x4b; 32], request_id, &admission).expect("registration");
        let evidence = vec![0x4c; MAX_EXECUTOR_PROOF_EVIDENCE_BYTES];
        let evidence_commitment = roster_executor_evidence_commitment(&evidence);
        let commitments = admission
            .members()
            .iter()
            .map(|member| {
                stable_terminal_proof_commitment(
                    binding,
                    registration,
                    &admission,
                    Phase::Established,
                    member,
                    RosterProviderOutcomeV1::AppliedExecuted,
                    evidence_commitment,
                )
                .expect("stable proof")
            })
            .collect();
        let terminal = TerminalRecord::new(&admission, request_id, Phase::Established, commitments)
            .expect("terminal");
        let executor_subject = [0x4d; 32];
        let terminal_binding = RosterCompactTerminalEvidenceBindingV2::for_terminal(
            identity,
            binding,
            registration,
            &provenance,
            &admission,
            &authority,
            &terminal,
            executor_subject,
        )
        .expect("terminal compact binding");
        let proofs = admission
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
                    proof_epoch: 19,
                    provider_operation: RosterProviderOperationV1::Execute,
                    outcome: RosterProviderOutcomeV1::AppliedExecuted,
                    evidence_length: evidence.len() as u16,
                    evidence_commitment,
                    stable_proof_commitment: *stable_proof_commitment,
                };
                let signature = sign_digest(
                    &executor_leaf,
                    RosterCompactTerminalMemberSigningInputV2 {
                        binding: terminal_binding.clone(),
                        member: member.clone(),
                    }
                    .digest()
                    .expect("terminal member digest"),
                );
                let provider_certificate = compact_certificate(
                    &root,
                    &root_key,
                    &executor_leaf,
                    RosterAttestationCertificateRoleV1::Provider,
                    identity,
                    admission.scope().digest(),
                    [0x4e; 32],
                );
                let provider = RosterAttestationLeafCertificateV1::issue_from_signed_parts(
                    &root,
                    provider_certificate.clone(),
                )
                .expect("provider certificate");
                RosterCompactTerminalMemberProofPartsV2 {
                    provider_signature: sign_digest(
                        &executor_leaf,
                        provider_receipt_compact_digest(&terminal_binding, &member, &provider)
                            .expect("provider digest"),
                    ),
                    provider_certificate,
                    member,
                    signature,
                }
            })
            .collect();
        let executor_certificate = compact_certificate(
            &root,
            &root_key,
            &executor_leaf,
            RosterAttestationCertificateRoleV1::Executor,
            identity,
            admission.scope().digest(),
            executor_subject,
        );
        let terminal_evidence = RosterCompactTerminalEvidenceV2::issue_from_signed_parts(
            &root,
            executor_certificate,
            &terminal_binding,
            proofs,
        )
        .expect("compact terminal evidence");
        (
            root,
            identity,
            admission,
            binding,
            authority,
            registration,
            ingress,
            provenance,
            terminal,
            terminal_evidence,
        )
    }

    #[test]
    fn shared_session_key_commitment_preserves_the_frozen_binding_digest() {
        let key = key();
        let mut legacy = Sha256::new();
        legacy.update(SESSION_KEY_BINDING_DOMAIN);
        update_len_prefixed(&mut legacy, &key.canonical_digest_input());
        let expected: [u8; 32] = legacy.finalize().into();

        assert_eq!(session_key_commitment(&key), expected);
        assert_eq!(
            request_binding_key(
                1,
                Scope::from_digest([9; 32]),
                &key,
                RosterId::from_bytes([7; ROSTER_ID_BYTES]).expect("roster ID"),
            )
            .expect("binding")
            .session_key_commitment(),
            expected
        );
    }

    fn proposal(width: usize) -> Result<AdmissionProposal, Error> {
        AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([7; ROSTER_ID_BYTES]).unwrap(),
            (0..width)
                .map(|n| {
                    Member::new(
                        n as u8,
                        MemberOperationId::from_bytes([n as u8 + 1; MEMBER_OPERATION_ID_BYTES])
                            .unwrap(),
                        vec![n as u8 + 1],
                        1,
                    )
                    .unwrap()
                })
                .collect(),
            EstablishedMutation::no_op(),
            vec![1],
            vec![2],
            vec![3],
        )
    }
    fn admission() -> Admission {
        Admission::authenticate(
            proposal(FRESH_ROSTER_MEMBERS).unwrap(),
            key(),
            Scope::from_digest([9; 32]),
            OwnerId::new("owner").unwrap(),
            FenceToken::new(1),
            Generation::new(1),
        )
        .unwrap()
    }

    fn compacted_terminal_lookup<'a>(
        admission: &'a Admission,
        current_fence: FenceToken,
        current_generation: Generation,
    ) -> CompactedTerminalLookup<'a> {
        CompactedTerminalLookup {
            history_epoch: 4,
            scope: admission.scope(),
            key: admission.key(),
            roster_id: admission.roster_id(),
            original_owner: admission.logical_owner(),
            original_admission_fence: admission.admission_fence(),
            current_fence,
            current_generation,
        }
    }

    #[test]
    fn generic_roster_accepts_one_through_eight_members_with_six_as_the_fresh_target() {
        assert_eq!(proposal(0), Err(Error::MemberLimit));
        for width in 1..=MAX_MEMBERS {
            assert_eq!(proposal(width).unwrap().members().len(), width);
        }

        let too_many = (0..=MAX_MEMBERS)
            .map(|ordinal| {
                Member::new(
                    ordinal as u8,
                    MemberOperationId::from_bytes([ordinal as u8 + 1; MEMBER_OPERATION_ID_BYTES])
                        .unwrap(),
                    vec![ordinal as u8],
                    1,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            AdmissionProposal::new(
                Profile::v1(),
                RosterId::from_bytes([7; ROSTER_ID_BYTES]).unwrap(),
                too_many,
                EstablishedMutation::no_op(),
                vec![],
                vec![],
                vec![],
            ),
            Err(Error::MemberLimit)
        );
    }

    #[test]
    fn member_versions_match_the_wire_and_proof_contract_at_all_supported_widths() {
        let operation_id = MemberOperationId::from_bytes([0x71; MEMBER_OPERATION_ID_BYTES])
            .expect("nonzero test member operation ID");
        assert_eq!(
            Member::new(0, operation_id, vec![1], 0),
            Err(Error::InvalidMember)
        );

        for (width, expected_version) in [(1, 1), (MAX_MEMBERS, u64::MAX)] {
            let members = (0..width)
                .map(|ordinal| {
                    Member::new(
                        ordinal as u8,
                        MemberOperationId::from_bytes(
                            [ordinal as u8 + 1; MEMBER_OPERATION_ID_BYTES],
                        )
                        .expect("nonzero test member operation ID"),
                        vec![ordinal as u8 + 1],
                        expected_version,
                    )
                    .expect("supported nonzero member version")
                })
                .collect();
            let value = AdmissionProposal::new(
                Profile::v1(),
                RosterId::from_bytes([0x72; ROSTER_ID_BYTES]).unwrap(),
                members,
                EstablishedMutation::no_op(),
                vec![],
                vec![],
                vec![],
            )
            .expect("supported roster width and version");
            assert_eq!(value.members().len(), width);
            assert!(value
                .members()
                .iter()
                .all(|member| member.expected_version() == expected_version));
        }

        let invalid_member = Member {
            ordinal: 0,
            operation_id,
            descriptor: vec![1],
            expected_version: 0,
        };
        assert_eq!(
            AdmissionProposal::new(
                Profile::v1(),
                RosterId::from_bytes([0x73; ROSTER_ID_BYTES]).unwrap(),
                vec![invalid_member],
                EstablishedMutation::no_op(),
                vec![],
                vec![],
                vec![],
            ),
            Err(Error::InvalidMember),
            "the admission validation boundary rejects malformed in-memory values too"
        );
    }

    #[test]
    fn frozen_profile_digest_and_widths() {
        assert_eq!(CONSUMER_ALPN, b"opc-session-consumer/3");
        assert_eq!(MAX_MEMBERS, 8);
        assert_eq!(FRESH_ROSTER_MEMBERS, 6);
        assert_eq!(ROSTER_ID_BYTES, 16);
        assert_eq!(MEMBER_OPERATION_ID_BYTES, 16);
        assert_eq!(PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES, 274_877_906_944);
        assert_eq!(CHARGE_WITNESS_VERSION, 1);
        assert_eq!(MAX_COMMITTED_TERMINAL_CODEC_BYTES, 1_069_519);
        let profile_lines: BTreeSet<&[u8]> =
            PROFILE_DESCRIPTOR.split(|byte| *byte == b'\n').collect();
        assert!(profile_lines.iter().any(|line| {
            line.starts_with(b"domains=")
                && line
                    .windows(b"roster-attestation-provider-receipt".len())
                    .any(|part| part == b"roster-attestation-provider-receipt")
        }));
        assert!(profile_lines.contains(
            b"magics=OPCRAD2\\0,OPCRTM2\\0,OPCRCT1\\0,OPCRTB1\\0,OPCRHF1\\0,OPCPRC1\\0".as_slice()
        ));
        assert!(profile_lines.iter().any(|line| {
            line.starts_with(b"limits=")
                && line
                    .windows(b"attestation-bundle:40960".len())
                    .any(|part| part == b"attestation-bundle:40960")
                && line
                    .windows(b"compact-terminal-evidence:8192".len())
                    .any(|part| part == b"compact-terminal-evidence:8192")
        }));
        assert!(profile_lines.contains(
            b"committed-terminal-frame-field-order=record,commit-metadata(sequence,raft-log-index,committed-at),committing-registration-handle,committing-registration-request-id,committing-registration-terminal-slot-id,committing-authority-scope,committing-authority-key,committing-authority-owner,committing-authority-fence,committing-authority-credential,committing-authority-generation,committing-authority-acquired-at,committing-authority-expires-at,committing-guard-commitment,materialization,receipt-commitment;materialization-postcard-tags=updated:0,deleted:1,no-op:2,aborted:3".as_slice()
        ));
        assert!(profile_lines.contains(
            b"terminal-guard-field-order=profile,committing-registration-handle,committing-registration-request-id,committing-registration-terminal-slot-id,admission-commitment,scope,key,owner,fence,credential,generation,acquired-at,expires-at".as_slice()
        ));
        assert!(profile_lines.contains(
            b"established-put=authoritative-session,exact-admitted-envelope-v1,original-owner-fence,successor-generation,no-expiry".as_slice()
        ));
        assert!(profile_lines.contains(
            b"admission-business-reservation=exact-present-generation,key-exclusive-through-terminalization,complete-protected-checkpoint-validation,generation-overflow-rejected-before-effects".as_slice()
        ));
        assert!(profile_lines.contains(
            b"aggregate-storage=deterministic-roster-ledger-schema-charge,dedicated-roster-snapshot-materialized-plus-future-reserved-budget,admission-reserves-terminal-peak,terminal-converts-without-capacity-check,reclaim-retained-to-tombstone,retirement-releases;charge-v1=page:4096,live-row:512,retained-row:384,tombstone-row:128,live-index:192,retained-index:160,tombstone-index:96,receipt-overhead-max:4096,business-header-max:4096".as_slice()
        ));
        assert!(profile_lines.contains(
            b"roster-local-charge=deterministic-roster-ledger-logical-schema-charge-only,not-raw-sqlite-or-global-store-cap;PROTECTED_ROSTER_LOGICAL_BUDGET_BYTES=274877906944,CHARGE_WITNESS_VERSION=1".as_slice()
        ));
        assert!(profile_lines.contains(
            b"provider-scheduling=fail-fast,global-max:1024,exact-tenant-scope-cap:ceil(global/2),fixed-shards:16,no-wait-queue,no-per-subscriber-resource".as_slice()
        ));
        assert!(profile_lines.contains(
            b"maintenance=bounded-deterministic-reclaim-and-retirement,payload-compaction,irreversible-floor-retirement;never-on-fresh-success;local-provider-journal-only".as_slice()
        ));
        assert!(profile_lines.contains(
            b"terminal=phase-inferred-from-complete-local-provider-proofs,prepared-body-local,first-conclusive-member-outcome-and-evidence-commitment-immutable-across-successors,established-alone-mints-publication-authority,aborted-nonpublishing,checkpoint-and-result-retained-exactly-through-terminal-retention,then-full-copies-atomically-deleted-and-payload-compacted-to-nonpublishing-conflict-status".as_slice()
        ));
        assert!(profile_lines.contains(
            b"publication=provider-local-durable-inert-intent-then-adopt,no-consensus-mutation,stable-id-excludes-replaceable-current-fence,current-authority-read-before-and-after-effect,status-first,monotonic-state:absent-to-reserved-to-attempted-to-published,conflict-sticky,created-state-never-reverts-to-absent,logical-state-may-compact-but-not-gc,absent-non-exclusionary-never-effect-authority,begin-never-crosses-effect,adopt-durably-marks-attempted-before-effect,attempted-resend-only-after-provider-retained-exact-not-transmitted,each-call-atomically-raises-durable-fence-floor-and-rejects-lower-or-expired-before-io,outcome-unknown-status-adopt-only,published-tombstone-outlives-terminal-retention,ack-only-after-exact-established-and-postcheck".as_slice()
        ));
        assert!(PROFILE_DESCRIPTOR
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"provider-fence=atomically-track-monotonic-current-execution-fence-per-exact-member-binding(roster-id,admission-commitment,scope,tenant,ordinal,stable-member-operation-id,descriptor,expected-version),reject-delayed-lower-fence-execute-after-higher-fence-status-or-adopt-conclusive-not-applied-or-compensated"));
        assert!(PROFILE_DESCRIPTOR
            .split(|byte| *byte == b'\n')
            .any(|line| line == b"history=stable-slot-binds-epoch-scope-session-key-roster-id,new-v2-admission-atomically-selects-binds-current-epoch-greater-than-durable-exact-scope-floor-before-reserve,admit-reserves-one-terminal-slot,terminal-retention-starts-at-terminalization,reclaim-oldest-min-1024-eligible-to-v2-conflict-tombstone,never-reclaim-live,durable-canonical-scope-bound-irreversible-floor,never-reopen-before-scope-bound-irreversible-epoch-retirement"));
        assert!(PROFILE_DESCRIPTOR
            .split(|byte| *byte == b'\n')
            .any(|line| line.starts_with(b"executor-field-order=")
                && line.windows(b"provider-receipt=".len()).any(|part| part == b"provider-receipt=")
                && line.windows(b"roles:executor|provider|transport-ingress".len()).any(|part| part == b"roles:executor|provider|transport-ingress")
                && line.windows(b"provider-operations=local-prepare-execute-status-adopt-compensate-reconcile".len()).any(|part| part == b"provider-operations=local-prepare-execute-status-adopt-compensate-reconcile")));
        assert_eq!(
            PROOF_DOMAIN,
            b"opc/session-store/protected-roster/executor-proof/v1\0"
        );
        assert_eq!(
            EXECUTOR_EVIDENCE_DOMAIN,
            b"opc/session-store/protected-roster/executor-evidence/v1\0"
        );
        assert_eq!(
            [
                PROVIDER_OPERATION_EXECUTE_TAG,
                PROVIDER_OPERATION_STATUS_TAG,
                PROVIDER_OPERATION_ADOPT_TAG,
                PROVIDER_OPERATION_COMPENSATE_TAG,
                PROVIDER_OPERATION_PREPARE_TAG,
                PROVIDER_OPERATION_RECONCILE_TAG,
            ],
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!([PHASE_ESTABLISHED, PHASE_ABORTED], [1, 2]);
        assert_eq!(
            [
                PROVIDER_NOT_TRANSMITTED,
                PROVIDER_OUTCOME_UNKNOWN,
                PROVIDER_NOT_FOUND,
                PROVIDER_PENDING,
                PROVIDER_CONCLUSIVE,
                PROVIDER_PREPARED_NOT_RUN,
                PROVIDER_READY_TO_PREPARE,
            ],
            [1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            [
                OUTCOME_APPLIED_EXECUTED,
                OUTCOME_APPLIED_ADOPTED,
                OUTCOME_NOT_APPLIED_RECONCILED,
                OUTCOME_COMPENSATED_RECONCILED,
            ],
            [1, 2, 3, 4]
        );
        assert_eq!(
            [
                PUBLICATION_OPERATION_STATUS_TAG,
                PUBLICATION_OPERATION_BEGIN_INTENT_TAG,
                PUBLICATION_OPERATION_ADOPT_TAG,
            ],
            [1, 2, 3]
        );
        assert_eq!(
            [
                PUBLICATION_ABSENT,
                PUBLICATION_NOT_TRANSMITTED,
                PUBLICATION_OUTCOME_UNKNOWN,
                PUBLICATION_PENDING,
                PUBLICATION_PUBLISHED,
                PUBLICATION_CONFLICT,
            ],
            [1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            profile_digest(),
            [
                0x1f, 0xc9, 0xe4, 0xbd, 0xaf, 0xfd, 0x17, 0x46, 0xf1, 0xaf, 0x8d, 0x21, 0xc7, 0xb7,
                0x34, 0x37, 0xc5, 0xba, 0x14, 0x22, 0x8e, 0xc4, 0x3b, 0xe4, 0xe2, 0xcf, 0x18, 0x2c,
                0x6a, 0x3d, 0xda, 0x35,
            ]
        );
    }

    #[test]
    fn reconcile_is_the_only_negative_or_compensation_terminal_operation() {
        use RosterProviderOperationV1::{Adopt, Compensate, Execute, Prepare, Reconcile, Status};
        use RosterProviderOutcomeV1::{
            AppliedAdopted, AppliedExecuted, CompensatedReconciled, NotAppliedReconciled,
        };

        assert!(attested_provider_outcome_allowed(Execute, AppliedExecuted));
        assert!(!attested_provider_outcome_allowed(
            Execute,
            NotAppliedReconciled
        ));
        assert!(!attested_provider_outcome_allowed(
            Execute,
            CompensatedReconciled
        ));
        assert!(attested_provider_outcome_allowed(Adopt, AppliedAdopted));
        assert!(attested_provider_outcome_allowed(Status, AppliedExecuted));
        assert!(attested_provider_outcome_allowed(Status, AppliedAdopted));
        assert!(attested_provider_outcome_allowed(
            Reconcile,
            NotAppliedReconciled
        ));
        assert!(attested_provider_outcome_allowed(
            Reconcile,
            CompensatedReconciled
        ));
        assert!(!attested_provider_outcome_allowed(
            Compensate,
            CompensatedReconciled
        ));
        assert!(!attested_provider_outcome_allowed(Prepare, AppliedExecuted));
    }

    #[test]
    fn irreversible_floor_canonical_rehydration_is_strictly_scoped_and_monotonic() {
        let scope = Scope::from_digest([9; 32]);
        let next_admission = admission();
        let initial =
            IrreversibleHistoryFloor::initial(next_admission.binding_key(1).unwrap()).unwrap();
        let advanced = initial.advance_to(4).unwrap();
        let frame = advanced.to_canonical_bytes().unwrap();
        assert_eq!(&frame[..8], &HISTORY_FLOOR_FRAME_MAGIC);
        assert!(frame.len() <= MAX_HISTORY_FLOOR_CODEC_BYTES);
        assert_eq!(
            frame_sha256(&frame),
            [
                0x4a, 0xbb, 0x3a, 0xf8, 0xb4, 0xf0, 0xb7, 0xca, 0xb7, 0xa0, 0x44, 0x2a, 0x47, 0xd8,
                0xa3, 0x8c, 0x3f, 0xe2, 0xc1, 0x01, 0x8c, 0xaa, 0x07, 0x79, 0x31, 0xaa, 0x4c, 0xba,
                0xa8, 0x59, 0x83, 0x5f,
            ]
        );
        let rehydrated = IrreversibleHistoryFloor::from_canonical_bytes(&frame).unwrap();
        assert_eq!(rehydrated.scope, scope);
        assert_eq!(rehydrated.retired_through(), 4);
        assert_eq!(rehydrated, advanced);
        assert!(rehydrated.strictly_advances(initial).is_ok());
        assert_eq!(
            rehydrated.validate_new_binding(next_admission.binding_key(4).unwrap()),
            Err(Error::InvalidHistory)
        );
        assert!(rehydrated
            .permits_binding(next_admission.binding_key(4).unwrap())
            .is_ok());
        assert_eq!(
            rehydrated.permits_binding(next_admission.binding_key(5).unwrap()),
            Err(Error::InvalidHistory)
        );
        let other_scope_admission = Admission::authenticate(
            next_admission.proposal.clone(),
            next_admission.key.clone(),
            Scope::from_digest([8; 32]),
            next_admission.logical_owner.clone(),
            next_admission.admission_fence,
            next_admission.expected_generation,
        )
        .unwrap();
        assert_eq!(
            rehydrated.permits_binding(other_scope_admission.binding_key(4).unwrap()),
            Err(Error::InvalidAuthority)
        );
        let mut other_tenant_key = next_admission.key.clone();
        other_tenant_key.tenant = TenantId::from_static("other-tenant");
        let other_tenant_admission = Admission::authenticate(
            next_admission.proposal.clone(),
            other_tenant_key,
            next_admission.scope,
            next_admission.logical_owner.clone(),
            next_admission.admission_fence,
            next_admission.expected_generation,
        )
        .unwrap();
        assert_eq!(
            rehydrated.validate_new_binding(other_tenant_admission.binding_key(5).unwrap()),
            Err(Error::InvalidAuthority)
        );
        assert_eq!(
            rehydrated.permits_binding(other_tenant_admission.binding_key(4).unwrap()),
            Err(Error::InvalidAuthority)
        );
        assert_eq!(
            rehydrated
                .validate_new_binding(next_admission.binding_key(4).unwrap())
                .and_then(|()| RequestId::bind(4, &next_admission).map(|_| ())),
            Err(Error::InvalidHistory)
        );
        assert!(rehydrated
            .validate_new_binding(next_admission.binding_key(5).unwrap())
            .and_then(|()| RequestId::bind(5, &next_admission).map(|_| ()))
            .is_ok());
        assert_eq!(
            initial.strictly_advances(rehydrated),
            Err(Error::InvalidHistory)
        );
        assert_eq!(rehydrated.advance_to(4), Err(Error::InvalidHistory));
        assert_eq!(rehydrated.advance_to(3), Err(Error::InvalidHistory));

        let other_scope_admission = Admission::authenticate(
            next_admission.proposal.clone(),
            next_admission.key.clone(),
            Scope::from_digest([8; 32]),
            next_admission.logical_owner.clone(),
            next_admission.admission_fence,
            next_admission.expected_generation,
        )
        .unwrap();
        let other_scope =
            IrreversibleHistoryFloor::initial(other_scope_admission.binding_key(1).unwrap())
                .unwrap()
                .advance_to(5)
                .unwrap();
        assert_eq!(
            other_scope.strictly_advances(rehydrated),
            Err(Error::InvalidAuthority)
        );

        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(
            IrreversibleHistoryFloor::from_canonical_bytes(&trailing),
            Err(Error::InvalidEncoding)
        );
        let invalid_scope = encode_frame(
            HISTORY_FLOOR_FRAME_MAGIC,
            HISTORY_FLOOR_FRAME_DOMAIN,
            &([0; 32], [1; 32], 4_u64),
            MAX_HISTORY_FLOOR_CODEC_BYTES,
        )
        .unwrap();
        assert_eq!(
            IrreversibleHistoryFloor::from_canonical_bytes(&invalid_scope),
            Err(Error::InvalidAuthority)
        );
        let invalid_epoch = encode_frame(
            HISTORY_FLOOR_FRAME_MAGIC,
            HISTORY_FLOOR_FRAME_DOMAIN,
            &([9; 32], [1; 32], MAX_HISTORY_EPOCH + 1),
            MAX_HISTORY_FLOOR_CODEC_BYTES,
        )
        .unwrap();
        assert_eq!(
            IrreversibleHistoryFloor::from_canonical_bytes(&invalid_epoch),
            Err(Error::InvalidHistory)
        );
    }

    #[test]
    fn canonical_frames_match_frozen_compact_goldens() {
        let admission = admission();
        let admission_frame = admission.to_canonical_bytes().unwrap();
        assert_eq!(&admission_frame[..8], &ADMISSION_FRAME_MAGIC);
        assert_eq!(
            frame_sha256(&admission_frame),
            [
                0x15, 0x01, 0x83, 0x78, 0x2f, 0x28, 0x34, 0xd7, 0x9e, 0x5b, 0xc1, 0x93, 0x6b, 0x92,
                0x20, 0x9f, 0xde, 0x7a, 0xa0, 0x29, 0xd9, 0xff, 0x63, 0xf5, 0xb6, 0x82, 0xf9, 0x02,
                0xae, 0xed, 0x51, 0x05,
            ]
        );
        let decoded_admission = Admission::from_canonical_bytes(&admission_frame).unwrap();
        assert_eq!(decoded_admission, admission);
        assert_eq!(
            decoded_admission.body_commitment(),
            admission.body_commitment()
        );
        let mut admission_trailing = admission_frame.clone();
        admission_trailing.push(0);
        assert_eq!(
            Admission::from_canonical_bytes(&admission_trailing),
            Err(Error::InvalidEncoding)
        );

        let terminal = TerminalRecord::new(
            &admission,
            RequestId::bind(4, &admission).unwrap(),
            Phase::Established,
            vec![[1; 32]; FRESH_ROSTER_MEMBERS],
        )
        .unwrap();
        let terminal_frame = terminal.to_canonical_bytes(&admission).unwrap();
        assert_eq!(&terminal_frame[..8], &TERMINAL_FRAME_MAGIC);
        assert_eq!(
            frame_sha256(&terminal_frame),
            [
                0xa1, 0xcd, 0xa1, 0x64, 0x2c, 0x6a, 0x50, 0x4d, 0x26, 0x9c, 0x5a, 0x69, 0x9f, 0x5a,
                0x32, 0x5a, 0x33, 0x90, 0x51, 0xc6, 0x53, 0x7c, 0x9c, 0x9a, 0x99, 0x4f, 0xe5, 0x95,
                0x69, 0xdb, 0x02, 0x7e,
            ]
        );
        let mut terminal_trailing = terminal_frame.clone();
        terminal_trailing.push(0);
        assert_eq!(
            TerminalRecord::from_canonical_bytes(&terminal_trailing, &admission),
            Err(Error::InvalidEncoding)
        );
    }

    #[test]
    fn admission_frame_field_order_is_proposal_key_scope_owner_fence_generation() {
        let admission = admission();
        let frame = admission.to_canonical_bytes().unwrap();
        let body_len = u32::from_be_bytes([frame[10], frame[11], frame[12], frame[13]]) as usize;
        let expected = postcard::to_allocvec(&(
            admission.proposal.clone(),
            admission.key.clone(),
            admission.scope.digest(),
            admission.logical_owner.clone(),
            admission.admission_fence,
            admission.expected_generation,
        ))
        .unwrap();
        assert_eq!(
            &frame[FRAME_HEADER_BYTES..FRAME_HEADER_BYTES + body_len],
            expected
        );
    }
    #[test]
    fn proposal_authentication_is_separate() {
        let p = proposal(FRESH_ROSTER_MEMBERS).unwrap();
        let a = Admission::authenticate(
            p.clone(),
            key(),
            Scope::from_digest([1; 32]),
            OwnerId::new("owner").unwrap(),
            FenceToken::new(1),
            Generation::new(2),
        )
        .unwrap();
        assert_eq!(a.roster_id(), p.roster_id());
        assert!(Admission::authenticate(
            p,
            key(),
            Scope::from_digest([0; 32]),
            OwnerId::new("owner").unwrap(),
            FenceToken::new(1),
            Generation::new(2)
        )
        .is_err());
    }
    #[test]
    fn protected_plan_checkpoint_and_result_have_independent_exact_bounds() {
        let roster_id = RosterId::from_bytes([1; ROSTER_ID_BYTES]).unwrap();
        let members = || {
            (0..FRESH_ROSTER_MEMBERS)
                .map(|ordinal| {
                    Member::new(
                        ordinal as u8,
                        MemberOperationId::from_bytes(
                            [ordinal as u8 + 2; MEMBER_OPERATION_ID_BYTES],
                        )
                        .unwrap(),
                        vec![1],
                        1,
                    )
                    .unwrap()
                })
                .collect()
        };
        let maximum = AdmissionProposal::new(
            Profile::v1(),
            roster_id,
            members(),
            EstablishedMutation::no_op(),
            vec![0; MAX_PLAN_BYTES],
            vec![0; MAX_CHECKPOINT_BYTES],
            vec![0; MAX_RESULT_BYTES],
        )
        .unwrap();
        assert_eq!(maximum.protected_plan().len(), MAX_PLAN_BYTES);
        assert_eq!(maximum.terminal_checkpoint().len(), MAX_CHECKPOINT_BYTES);
        assert_eq!(maximum.terminal_result().len(), MAX_RESULT_BYTES);

        assert_eq!(
            AdmissionProposal::new(
                Profile::v1(),
                roster_id,
                members(),
                EstablishedMutation::no_op(),
                vec![0; MAX_PLAN_BYTES + 1],
                vec![],
                vec![],
            ),
            Err(Error::PlanTooLarge)
        );
        assert_eq!(
            AdmissionProposal::new(
                Profile::v1(),
                roster_id,
                members(),
                EstablishedMutation::no_op(),
                vec![],
                vec![0; MAX_CHECKPOINT_BYTES + 1],
                vec![],
            ),
            Err(Error::CheckpointTooLarge)
        );
        assert_eq!(
            AdmissionProposal::new(
                Profile::v1(),
                roster_id,
                members(),
                EstablishedMutation::no_op(),
                vec![],
                vec![],
                vec![0; MAX_RESULT_BYTES + 1],
            ),
            Err(Error::ResultTooLarge)
        );
    }

    #[test]
    fn established_mutation_is_immutable_bounded_and_checkpoint_backed() {
        let state_type = StateType::from_static("authoritative-final-attach");
        let put = EstablishedMutation::put_checkpoint(state_type);
        assert_eq!(put.tag(), ESTABLISHED_MUTATION_PUT_CHECKPOINT);
        assert_eq!(
            put.state_type().map(StateType::as_str),
            Some("authoritative-final-attach")
        );

        let fresh_members: Vec<_> = (0..FRESH_ROSTER_MEMBERS)
            .map(|ordinal| {
                Member::new(
                    ordinal as u8,
                    MemberOperationId::from_bytes([ordinal as u8 + 2; MEMBER_OPERATION_ID_BYTES])
                        .unwrap(),
                    vec![1],
                    1,
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            AdmissionProposal::new(
                Profile::v1(),
                RosterId::from_bytes([1; ROSTER_ID_BYTES]).unwrap(),
                fresh_members.clone(),
                put,
                vec![1],
                vec![],
                vec![3],
            ),
            Err(Error::InvalidEstablishedMutation)
        );

        let invalid = EstablishedMutationWire {
            tag: 0xff,
            state_type: None,
        };
        let bytes = postcard::to_allocvec(&invalid).unwrap();
        assert!(postcard::from_bytes::<EstablishedMutation>(&bytes).is_err());

        let overflow_proposal = AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([3; ROSTER_ID_BYTES]).unwrap(),
            fresh_members,
            EstablishedMutation::put_checkpoint(StateType::from_static("terminal")),
            vec![1],
            vec![2],
            vec![3],
        )
        .unwrap();
        assert_eq!(
            Admission::authenticate(
                overflow_proposal,
                key(),
                Scope::from_digest([9; 32]),
                OwnerId::new("owner").unwrap(),
                FenceToken::new(1),
                Generation::new(u64::MAX),
            ),
            Err(Error::InvalidEstablishedMutation)
        );
    }

    #[test]
    fn admission_commitment_binds_every_established_mutation_field() {
        let original = admission();
        let reauthenticate = |mutation| {
            let mut proposal = original.proposal.clone();
            proposal.established_mutation = mutation;
            Admission::authenticate(
                proposal,
                original.key.clone(),
                original.scope,
                original.logical_owner.clone(),
                original.admission_fence,
                original.expected_generation,
            )
            .unwrap()
        };
        let deleted = reauthenticate(EstablishedMutation::delete());
        assert_ne!(original.body_commitment(), deleted.body_commitment());

        let first_put = reauthenticate(EstablishedMutation::put_checkpoint(
            StateType::from_static("final-a"),
        ));
        let second_put = reauthenticate(EstablishedMutation::put_checkpoint(
            StateType::from_static("final-b"),
        ));
        assert_ne!(first_put.body_commitment(), second_put.body_commitment());
    }
    #[test]
    fn terminal_binds_order_tamper_and_restart_bytes() {
        let a = admission();
        let r = RequestId::bind(4, &a).unwrap();
        let record = TerminalRecord::new(
            &a,
            r,
            Phase::Established,
            vec![[1; 32]; FRESH_ROSTER_MEMBERS],
        )
        .unwrap();
        let bytes = record.to_canonical_bytes(&a).unwrap();
        assert_eq!(
            TerminalRecord::from_canonical_bytes(&bytes, &a).unwrap(),
            record
        );
        let other = TerminalRecord::new(&a, r, Phase::Aborted, vec![[2; 32]; FRESH_ROSTER_MEMBERS])
            .unwrap();
        assert_ne!(record.body_commitment(), other.body_commitment());
        let mut tampered = bytes;
        tampered[FRAME_HEADER_BYTES] ^= 1;
        assert_eq!(
            TerminalRecord::from_canonical_bytes(&tampered, &a),
            Err(Error::InvalidEncoding)
        );
    }

    #[test]
    fn terminal_slots_conflict_changed_bodies_and_isolate_scope_and_session_key() {
        let admission = admission();
        let request_id = RequestId::bind(4, &admission).unwrap();
        let terminal_slot = request_id.terminal_slot_id(&admission).unwrap();

        let mut changed_proposal = admission.proposal.clone();
        changed_proposal.protected_plan.push(4);
        let changed_body = Admission::authenticate(
            changed_proposal,
            admission.key.clone(),
            admission.scope,
            admission.logical_owner.clone(),
            admission.admission_fence,
            admission.expected_generation,
        )
        .unwrap();
        let changed_request_id = RequestId::bind(4, &changed_body).unwrap();
        assert_ne!(request_id, changed_request_id);
        assert_eq!(
            terminal_slot,
            changed_request_id.terminal_slot_id(&changed_body).unwrap()
        );

        let other_scope = Admission::authenticate(
            admission.proposal.clone(),
            admission.key.clone(),
            Scope::from_digest([8; 32]),
            admission.logical_owner.clone(),
            admission.admission_fence,
            admission.expected_generation,
        )
        .unwrap();
        let other_scope_id = RequestId::bind(4, &other_scope).unwrap();
        assert_ne!(
            terminal_slot,
            other_scope_id.terminal_slot_id(&other_scope).unwrap()
        );

        let mut other_key = admission.key.clone();
        other_key.tenant = TenantId::from_static("other-tenant");
        let other_key = Admission::authenticate(
            admission.proposal.clone(),
            other_key,
            admission.scope,
            admission.logical_owner.clone(),
            admission.admission_fence,
            admission.expected_generation,
        )
        .unwrap();
        let other_key_id = RequestId::bind(4, &other_key).unwrap();
        assert_ne!(
            terminal_slot,
            other_key_id.terminal_slot_id(&other_key).unwrap()
        );

        let established = TerminalRecord::new(
            &admission,
            request_id,
            Phase::Established,
            vec![[1; 32]; FRESH_ROSTER_MEMBERS],
        )
        .unwrap();
        let aborted = TerminalRecord::new(
            &admission,
            request_id,
            Phase::Aborted,
            vec![[2; 32]; FRESH_ROSTER_MEMBERS],
        )
        .unwrap();
        assert_ne!(established.body_commitment(), aborted.body_commitment());
        assert_eq!(
            established
                .request_id()
                .terminal_slot_id(&admission)
                .unwrap(),
            aborted.request_id().terminal_slot_id(&admission).unwrap()
        );
        assert_eq!(format!("{terminal_slot:?}"), "TerminalSlotId(<redacted>)");
    }

    #[test]
    fn equal_opaque_descriptors_are_valid_with_unique_member_ids() {
        let members = (0..FRESH_ROSTER_MEMBERS as u8)
            .map(|ordinal| {
                Member::new(
                    ordinal,
                    MemberOperationId::from_bytes([ordinal + 1; MEMBER_OPERATION_ID_BYTES])
                        .unwrap(),
                    vec![9],
                    1,
                )
                .unwrap()
            })
            .collect();
        assert!(AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([1; ROSTER_ID_BYTES]).unwrap(),
            members,
            EstablishedMutation::no_op(),
            vec![],
            vec![],
            vec![],
        )
        .is_ok());
    }
    #[test]
    fn compacted_terminal_tombstone_never_reopens_changed_body() {
        let original_admission = admission();
        let request_id = RequestId::bind(4, &original_admission).unwrap();
        let terminal = TerminalRecord::new(
            &original_admission,
            request_id,
            Phase::Established,
            vec![[1; 32]; FRESH_ROSTER_MEMBERS],
        )
        .unwrap();
        let tombstone = TerminalConflictTombstone::new(&original_admission, &terminal).unwrap();
        let binding = original_admission.binding_key(4).unwrap();
        let terminal_slot = *request_id
            .terminal_slot_id(&original_admission)
            .unwrap()
            .as_bytes();
        let terminal_bytes = terminal.to_canonical_bytes(&original_admission).unwrap();
        let terminal_body_commitment =
            TerminalRecord::canonical_body_commitment(&terminal_bytes).unwrap();
        assert_eq!(terminal_body_commitment, terminal.body_commitment());
        assert!(tombstone
            .validate_compacted_terminal(
                binding,
                request_id,
                terminal_slot,
                FenceToken::new(2),
                original_admission.expected_generation(),
                terminal_body_commitment,
            )
            .is_ok());
        assert_eq!(
            tombstone.validate_compacted_terminal(
                binding,
                request_id,
                terminal_slot,
                original_admission.admission_fence(),
                original_admission.expected_generation(),
                terminal_body_commitment,
            ),
            Err(Error::InvalidAuthority)
        );
        assert_eq!(
            tombstone.validate_compacted_terminal(
                binding,
                request_id,
                terminal_slot,
                FenceToken::new(2),
                original_admission.expected_generation(),
                [0xEE; 32],
            ),
            Err(Error::RequestConflict)
        );
        let mut forged = terminal.clone();
        forged.phase_tag = Phase::Aborted.tag();
        let forged_bytes = encode_frame(
            TERMINAL_FRAME_MAGIC,
            TERMINAL_FRAME_DOMAIN,
            &forged,
            MAX_TERMINAL_CODEC_BYTES,
        )
        .unwrap();
        assert_eq!(
            TerminalRecord::canonical_body_commitment(&forged_bytes),
            Err(Error::InvalidTerminal),
            "a canonical envelope cannot preserve a stale embedded body commitment"
        );
        let encoded = tombstone.to_canonical_bytes().unwrap();
        assert!(encoded.len() <= MAX_TOMBSTONE_CODEC_BYTES);
        drop(terminal);
        drop(original_admission);

        let tombstone = TerminalConflictTombstone::from_canonical_bytes(&encoded).unwrap();
        let exact = admission();
        let status = tombstone.validate_admission(4, &exact).unwrap();
        assert_eq!(status.phase, Phase::Established);
        assert_ne!(status.terminal_body_commitment, [0; 32]);
        assert_eq!(
            tombstone.validate_lookup(compacted_terminal_lookup(
                &exact,
                exact.admission_fence(),
                exact.expected_generation(),
            )),
            Err(Error::InvalidAuthority)
        );
        assert_eq!(
            tombstone
                .validate_lookup(compacted_terminal_lookup(
                    &exact,
                    FenceToken::new(2),
                    exact.expected_generation(),
                ))
                .unwrap(),
            status
        );
        let mut wrong_scope =
            compacted_terminal_lookup(&exact, FenceToken::new(2), exact.expected_generation());
        wrong_scope.scope = Scope::from_digest([8; 32]);
        assert_eq!(
            tombstone.validate_lookup(wrong_scope),
            Err(Error::InvalidAuthority)
        );
        let mut other_key = exact.key().clone();
        other_key.stable_id = StableId::new(Bytes::from_static(b"other-key")).unwrap();
        let mut wrong_key =
            compacted_terminal_lookup(&exact, FenceToken::new(2), exact.expected_generation());
        wrong_key.key = &other_key;
        assert_eq!(
            tombstone.validate_lookup(wrong_key),
            Err(Error::InvalidAuthority)
        );
        let mut other_tenant = exact.key().clone();
        other_tenant.tenant = TenantId::from_static("other-tenant");
        let mut wrong_tenant =
            compacted_terminal_lookup(&exact, FenceToken::new(2), exact.expected_generation());
        wrong_tenant.key = &other_tenant;
        assert_eq!(
            tombstone.validate_lookup(wrong_tenant),
            Err(Error::InvalidAuthority)
        );
        let mut wrong_roster_id =
            compacted_terminal_lookup(&exact, FenceToken::new(2), exact.expected_generation());
        wrong_roster_id.roster_id = RosterId::from_bytes([8; ROSTER_ID_BYTES]).unwrap();
        assert_eq!(
            tombstone.validate_lookup(wrong_roster_id),
            Err(Error::InvalidAuthority)
        );
        let mut wrong_epoch =
            compacted_terminal_lookup(&exact, FenceToken::new(2), exact.expected_generation());
        wrong_epoch.history_epoch = 5;
        assert_eq!(
            tombstone.validate_lookup(wrong_epoch),
            Err(Error::InvalidAuthority)
        );
        assert_eq!(
            tombstone.validate_lookup(compacted_terminal_lookup(
                &exact,
                FenceToken::new(2),
                Generation::new(exact.expected_generation().get() + 1),
            )),
            Err(Error::InvalidAuthority)
        );
        let wrong_original_owner = OwnerId::new("wrong-original-owner").unwrap();
        let mut wrong_owner =
            compacted_terminal_lookup(&exact, FenceToken::new(2), exact.expected_generation());
        wrong_owner.original_owner = &wrong_original_owner;
        assert_eq!(
            tombstone.validate_lookup(wrong_owner),
            Err(Error::InvalidAuthority)
        );
        let mut wrong_original_fence =
            compacted_terminal_lookup(&exact, FenceToken::new(3), exact.expected_generation());
        wrong_original_fence.original_admission_fence =
            FenceToken::new(exact.admission_fence().get() + 1);
        assert_eq!(
            tombstone.validate_lookup(wrong_original_fence),
            Err(Error::InvalidAuthority),
            "the compact lookup must bind the claimed original admission fence"
        );

        let reauthenticate = |proposal, scope, owner, fence| {
            Admission::authenticate(
                proposal,
                exact.key().clone(),
                scope,
                owner,
                fence,
                exact.expected_generation(),
            )
            .unwrap()
        };
        let mut changed_bodies = Vec::new();
        let mut changed_plan_proposal = exact.proposal.clone();
        changed_plan_proposal.protected_plan.push(4);
        changed_bodies.push(reauthenticate(
            changed_plan_proposal,
            exact.scope(),
            exact.logical_owner().clone(),
            exact.admission_fence(),
        ));
        let mut changed_checkpoint_proposal = exact.proposal.clone();
        changed_checkpoint_proposal.terminal_checkpoint.push(4);
        changed_bodies.push(reauthenticate(
            changed_checkpoint_proposal,
            exact.scope(),
            exact.logical_owner().clone(),
            exact.admission_fence(),
        ));
        let mut changed_result_proposal = exact.proposal.clone();
        changed_result_proposal.terminal_result.push(4);
        changed_bodies.push(reauthenticate(
            changed_result_proposal,
            exact.scope(),
            exact.logical_owner().clone(),
            exact.admission_fence(),
        ));
        changed_bodies.push(reauthenticate(
            exact.proposal.clone(),
            exact.scope(),
            OwnerId::new("other-owner").unwrap(),
            exact.admission_fence(),
        ));
        changed_bodies.push(reauthenticate(
            exact.proposal.clone(),
            exact.scope(),
            exact.logical_owner().clone(),
            FenceToken::new(2),
        ));
        for changed in changed_bodies {
            assert_eq!(
                tombstone.validate_admission(4, &changed),
                Err(Error::RequestConflict)
            );
        }

        let other_scope = reauthenticate(
            exact.proposal.clone(),
            Scope::from_digest([8; 32]),
            exact.logical_owner().clone(),
            exact.admission_fence(),
        );
        assert_eq!(
            tombstone.validate_admission(4, &other_scope),
            Err(Error::InvalidAuthority)
        );
    }
    #[test]
    fn frames_have_fixed_descriptor_bound_ceilings() {
        let max_proposal = AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([4; ROSTER_ID_BYTES]).unwrap(),
            (0..MAX_MEMBERS)
                .map(|ordinal| {
                    Member::new(
                        ordinal as u8,
                        MemberOperationId::from_bytes(
                            [ordinal as u8 + 1; MEMBER_OPERATION_ID_BYTES],
                        )
                        .unwrap(),
                        vec![ordinal as u8 + 1; MAX_DESCRIPTOR_BYTES],
                        u64::MAX,
                    )
                    .unwrap()
                })
                .collect(),
            EstablishedMutation::put_checkpoint(
                StateType::new("s".repeat(StateType::MAX_BYTES)).unwrap(),
            ),
            vec![0xa5; MAX_PLAN_BYTES],
            vec![0x3c; MAX_CHECKPOINT_BYTES],
            vec![0x5a; MAX_RESULT_BYTES],
        )
        .unwrap();
        let max_admission = Admission::authenticate(
            max_proposal,
            maximum_key(),
            Scope::from_digest([0x9d; 32]),
            maximum_owner(),
            FenceToken::new(u64::MAX),
            Generation::new(u64::MAX - 1),
        )
        .unwrap();
        let admission_frame = max_admission.to_canonical_bytes().unwrap();
        assert_eq!(admission_frame.len(), MAX_ADMISSION_CODEC_BYTES);
        assert_eq!(MAX_ADMISSION_CODEC_BYTES, 2_245_658);
        assert_eq!(
            Admission::from_canonical_bytes(&admission_frame).unwrap(),
            max_admission
        );
        assert_eq!(
            Admission::from_canonical_bytes(&vec![0; MAX_ADMISSION_CODEC_BYTES + 1]),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            Admission::from_canonical_bytes(&admission_frame[..admission_frame.len() - 1]),
            Err(Error::InvalidEncoding)
        );

        assert_eq!(
            RequestId::bind(MAX_HISTORY_EPOCH + 1, &max_admission),
            Err(Error::InvalidHistory)
        );
        let request_id = RequestId::bind(MAX_HISTORY_EPOCH, &max_admission).unwrap();
        let terminal = TerminalRecord::new(
            &max_admission,
            request_id,
            Phase::Aborted,
            vec![[0x9d; 32]; MAX_MEMBERS],
        )
        .unwrap();
        let terminal_frame = terminal.to_canonical_bytes(&max_admission).unwrap();
        assert_eq!(terminal_frame.len(), MAX_TERMINAL_CODEC_BYTES);
        assert_eq!(MAX_TERMINAL_CODEC_BYTES, 1_065_423);
        assert_eq!(
            TerminalRecord::from_canonical_bytes(&terminal_frame, &max_admission).unwrap(),
            terminal
        );
        assert_eq!(
            TerminalRecord::from_canonical_bytes(
                &vec![0; MAX_TERMINAL_CODEC_BYTES + 1],
                &max_admission,
            ),
            Err(Error::InvalidEncoding)
        );
        assert_eq!(
            TerminalRecord::from_canonical_bytes(
                &terminal_frame[..terminal_frame.len() - 1],
                &max_admission,
            ),
            Err(Error::InvalidEncoding)
        );
    }

    #[test]
    fn compact_v2_provenance_and_terminal_cover_one_and_eight_members() {
        for width in [1, MAX_MEMBERS] {
            let (
                root,
                identity,
                admission,
                binding,
                authority,
                registration,
                ingress,
                provenance,
                terminal,
                evidence,
            ) = compact_v2_fixture(width);
            verify_compact_admission_provenance_v2(CompactAdmissionProvenanceVerificationV2 {
                root: &root,
                configuration_identity: identity,
                binding,
                admission: &admission,
                original_authority: &authority,
                ingress: &ingress,
                provenance: &provenance,
            })
            .expect("exact compact admission provenance");
            verify_historical_compact_admission_provenance_v2(
                HistoricalCompactAdmissionProvenanceVerificationV2 {
                    root: &root,
                    configuration_identity: identity,
                    binding,
                    admission: &admission,
                    original_authority: &authority,
                    provenance: &provenance,
                },
            )
            .expect("stored compact admission provenance uses its own ingress projection");
            evidence
                .verify_raw_terminal(&admission, &terminal)
                .expect("raw terminal correspondence");
            drop(terminal);
            drop(admission);
            verify_compact_terminal_evidence_v2(CompactTerminalEvidenceVerificationV2 {
                root: &root,
                configuration_identity: identity,
                logical_time: compact_time(20),
                binding,
                registration,
                admission_provenance: &provenance,
                committing_authority: &authority,
                evidence: &evidence,
            })
            .expect("raw-free compact terminal verification");
            assert_eq!(
                RosterCompactAdmissionProvenanceV2::decode_canonical(
                    &provenance.canonical_bytes().expect("provenance bytes"),
                )
                .expect("provenance decode")
                .commitment()
                .expect("provenance commitment"),
                provenance.commitment().expect("provenance commitment")
            );
            assert_eq!(
                RosterCompactTerminalEvidenceV2::decode_canonical(
                    &evidence.canonical_bytes().expect("terminal bytes"),
                )
                .expect("terminal decode")
                .commitment()
                .expect("terminal commitment"),
                evidence.commitment().expect("terminal commitment")
            );
        }
    }

    #[test]
    fn raw_provider_receipt_digest_survives_compact_q2_projection() {
        let (
            _root,
            identity,
            admission,
            binding,
            authority,
            registration,
            _ingress,
            _provenance,
            _terminal,
            compact,
        ) = compact_v2_fixture(1);
        let proof = compact.proofs.first().expect("one compact member");
        let member = admission.members().first().expect("one admitted member");
        let certificate_parts = || RosterAttestationLeafCertificatePartsV1 {
            root_id: proof.provider_certificate.root_id,
            role: RosterAttestationCertificateRoleV1::Provider,
            configuration_identity: proof.provider_certificate.configuration_identity,
            scope: proof.provider_certificate.scope,
            subject_identity_commitment: proof.provider_certificate.subject_identity_commitment,
            leaf_epoch: proof.provider_certificate.leaf_epoch,
            key_id: proof.provider_certificate.key_id,
            not_before: proof.provider_certificate.not_before,
            not_after: proof.provider_certificate.not_after,
            public_key: proof.provider_certificate.public_key,
            root_signature: proof.provider_certificate.root_signature,
        };
        let (handle, request_id, terminal_slot) = registration.consensus_parts();
        let raw = RosterProviderReceiptSigningInputV1 {
            profile: admission.profile(),
            configuration_identity: identity,
            certificate_subject_identity_commitment: proof
                .provider_certificate
                .subject_identity_commitment,
            certificate_role: RosterAttestationCertificateRoleV1::Provider,
            binding: binding.to_bytes(),
            registration_handle: handle,
            registration_request_id: request_id.to_bytes(),
            registration_terminal_slot: *terminal_slot.as_bytes(),
            roster_id: *admission.roster_id().as_bytes(),
            admission_commitment: admission.body_commitment(),
            ordinal: member.ordinal(),
            member_operation_id: *member.operation_id().as_bytes(),
            descriptor: member.descriptor().to_vec(),
            descriptor_commitment: member.descriptor_commitment(),
            expected_member_version: member.expected_version(),
            admission_generation: admission.expected_generation().get(),
            authority_scope: authority.scope().digest(),
            authority_key_canonical: authority.key().canonical_digest_input(),
            authority_owner: authority.owner().as_str().as_bytes().to_vec(),
            authority_fence: authority.fence().get(),
            authority_credential_id: authority.credential_id(),
            authority_generation: authority.generation().get(),
            authority_acquired_at: authority.acquired_at(),
            authority_expires_at: authority.expires_at(),
            proof_epoch: proof.member.proof_epoch,
            provider_operation: proof.member.provider_operation,
            outcome: proof.member.outcome,
            evidence: vec![0x4c; MAX_EXECUTOR_PROOF_EVIDENCE_BYTES],
        };
        assert_eq!(
            raw.digest().expect("raw receipt digest"),
            provider_receipt_compact_digest(
                &compact.binding,
                &proof.member,
                &proof.provider_certificate,
            )
            .expect("same receipt digest from compact projection"),
            "Q2 must verify the Provider signature over the identical raw receipt preimage"
        );
        verify_roster_provider_receipt_v1(
            &_root,
            compact_time(20),
            certificate_parts(),
            &raw,
            &proof.provider_signature,
        )
        .expect("raw receipt verifies before compacting");
        let mut changed_outcome = raw.clone();
        changed_outcome.outcome = RosterProviderOutcomeV1::AppliedAdopted;
        assert!(verify_roster_provider_receipt_v1(
            &_root,
            compact_time(20),
            certificate_parts(),
            &changed_outcome,
            &proof.provider_signature,
        )
        .is_err());
        let mut changed_epoch = raw.clone();
        changed_epoch.proof_epoch += 1;
        assert!(verify_roster_provider_receipt_v1(
            &_root,
            compact_time(20),
            certificate_parts(),
            &changed_epoch,
            &proof.provider_signature,
        )
        .is_err());
        let mut changed_fence = raw.clone();
        changed_fence.authority_fence += 1;
        assert!(verify_roster_provider_receipt_v1(
            &_root,
            compact_time(20),
            certificate_parts(),
            &changed_fence,
            &proof.provider_signature,
        )
        .is_err());
        assert!(verify_roster_provider_receipt_v1(
            &_root,
            compact_time(20),
            certificate_parts(),
            &raw,
            &[0; ROSTER_ATTESTATION_P256_SIGNATURE_BYTES],
        )
        .is_err());
        assert!(verify_roster_provider_receipt_v1(
            &_root,
            authority
                .acquired_at()
                .add_seconds(-1)
                .expect("before lease"),
            certificate_parts(),
            &raw,
            &proof.provider_signature,
        )
        .is_err());
        verify_compact_terminal_evidence_v2(CompactTerminalEvidenceVerificationV2 {
            root: &_root,
            configuration_identity: identity,
            logical_time: compact_time(20),
            binding,
            registration,
            admission_provenance: &_provenance,
            committing_authority: &authority,
            evidence: &compact,
        })
        .expect("Q2 compact verification accepts the raw Provider signature");
    }

    #[test]
    fn compacted_tombstone_history_reauthenticates_slots_and_original_authority() {
        let (
            root,
            identity,
            admission,
            binding,
            authority,
            _registration,
            _ingress,
            provenance,
            terminal,
            evidence,
        ) = compact_v2_fixture(1);
        let tombstone = TerminalConflictTombstone::new(&admission, &terminal)
            .expect("compact terminal tombstone");
        let verify_evidence = |terminal_evidence: &RosterCompactTerminalEvidenceV2| {
            verify_compacted_tombstone_history_v2(CompactedTombstoneHistoryVerificationV2 {
                root: &root,
                configuration_identity: identity,
                binding,
                tombstone: &tombstone,
                admission_provenance: &provenance,
                terminal_evidence,
                original_owner: authority.owner(),
                original_fence: authority.fence().get(),
                original_credential_id: authority.credential_id(),
                original_generation: authority.generation().get(),
                original_acquired_at: authority.acquired_at(),
                original_expires_at: authority.expires_at(),
            })
        };
        let verified = verify_evidence(&evidence)
            .expect("signed compact history verifies without admission bytes");
        assert_eq!(verified.stable_slot(), compact_admission_slot(&admission));
        assert_eq!(
            verified.terminal_slot(),
            command_id(TERMINAL_SLOT_DOMAIN, binding)
        );

        let provider_key = SigningKey::from_bytes((&[0x45; 32]).into()).expect("provider leaf");
        let mut wrong_provider_signature = evidence.clone();
        wrong_provider_signature.proofs[0].provider_signature =
            sign_digest(&provider_key, [0xa1; 32]);
        assert!(
            verify_evidence(&wrong_provider_signature).is_err(),
            "restart must reject a canonical but body-invalid Provider signature"
        );

        let root_key = SigningKey::from_bytes((&[0x41; 32]).into()).expect("root key");
        let mut unrooted_provider = evidence.clone();
        unrooted_provider.proofs[0]
            .provider_certificate
            .root_signature = sign_digest(&root_key, [0xa2; 32]);
        assert!(
            verify_evidence(&unrooted_provider).is_err(),
            "restart must reject a structurally valid Provider certificate not signed by the root"
        );

        let substituted_owner = OwnerId::new("compacted-history-forged-owner").expect("owner");
        assert!(
            verify_compacted_tombstone_history_v2(CompactedTombstoneHistoryVerificationV2 {
                root: &root,
                configuration_identity: identity,
                binding,
                tombstone: &tombstone,
                admission_provenance: &provenance,
                terminal_evidence: &evidence,
                original_owner: &substituted_owner,
                original_fence: authority.fence().get(),
                original_credential_id: authority.credential_id(),
                original_generation: authority.generation().get(),
                original_acquired_at: authority.acquired_at(),
                original_expires_at: authority.expires_at(),
            })
            .is_err(),
            "a side-table owner substitution must not change a tombstone's stable identity"
        );
    }

    #[test]
    fn compact_v2_codecs_stay_within_exact_bounds_at_eight_members() {
        let (_, _, _, _, _, _, _, provenance, _, evidence) =
            compact_v2_fixture_with_maximum_projection(MAX_MEMBERS, true);
        let admission_bytes = provenance.canonical_bytes().expect("provenance bytes");
        let terminal_bytes = evidence.canonical_bytes().expect("terminal bytes");
        assert_eq!(admission_bytes.len(), 1_715);
        assert_eq!(terminal_bytes.len(), 5_909);
        assert!(
            admission_bytes.len() <= MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES,
            "{} <= {}",
            admission_bytes.len(),
            MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES
        );
        assert!(
            terminal_bytes.len() <= MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES,
            "{} <= {}",
            terminal_bytes.len(),
            MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES
        );
        assert_eq!(
            RosterCompactAdmissionProvenanceV2::decode_canonical(
                &admission_bytes[..admission_bytes.len() - 1]
            ),
            Err(RosterAttestationError)
        );
        assert_eq!(
            RosterCompactTerminalEvidenceV2::decode_canonical(
                &terminal_bytes[..terminal_bytes.len() - 1]
            ),
            Err(RosterAttestationError)
        );
        assert_eq!(
            RosterCompactAdmissionProvenanceV2::decode_canonical(&vec![
                0;
                MAX_ROSTER_COMPACT_ADMISSION_PROVENANCE_BYTES
                    + 1
            ]),
            Err(RosterAttestationError)
        );
        assert_eq!(
            RosterCompactTerminalEvidenceV2::decode_canonical(&vec![
                0;
                MAX_ROSTER_COMPACT_TERMINAL_EVIDENCE_BYTES
                    + 1
            ]),
            Err(RosterAttestationError)
        );
        let mut noncanonical = terminal_bytes.clone();
        noncanonical.push(0);
        assert_eq!(
            RosterCompactTerminalEvidenceV2::decode_canonical(&noncanonical),
            Err(RosterAttestationError)
        );
    }

    #[test]
    fn compact_v2_rejects_mutated_binding_members_and_signatures() {
        let (
            root,
            identity,
            admission,
            binding,
            authority,
            registration,
            ingress,
            mut provenance,
            terminal,
            mut evidence,
        ) = compact_v2_fixture(MAX_MEMBERS);
        let valid_provenance = provenance.clone();
        provenance.input.admission_fence = provenance.input.admission_fence.saturating_add(1);
        assert!(
            verify_compact_admission_provenance_v2(CompactAdmissionProvenanceVerificationV2 {
                root: &root,
                configuration_identity: identity,
                binding,
                admission: &admission,
                original_authority: &authority,
                ingress: &ingress,
                provenance: &provenance,
            })
            .is_err()
        );
        let wrong_root = roster_attestation_trust_root([0x92; 32], 0x41);
        assert!(
            verify_compact_admission_provenance_v2(CompactAdmissionProvenanceVerificationV2 {
                root: &wrong_root,
                configuration_identity: identity,
                binding,
                admission: &admission,
                original_authority: &authority,
                ingress: &ingress,
                provenance: &valid_provenance,
            })
            .is_err()
        );

        let (_, _, _, _, _, _, _, _, _, mut reordered) = compact_v2_fixture(MAX_MEMBERS);
        reordered.proofs.swap(0, 1);
        assert!(reordered.canonical_bytes().is_err());
        let mut duplicated = evidence.clone();
        duplicated.proofs.push(duplicated.proofs[0].clone());
        assert!(duplicated.canonical_bytes().is_err());

        evidence.proofs[0].member.member_operation_id = [0x91; MEMBER_OPERATION_ID_BYTES];
        evidence.proofs[0].signature = sign_digest(
            &SigningKey::from_bytes((&[0x45; 32]).into()).expect("executor leaf"),
            RosterCompactTerminalMemberSigningInputV2 {
                binding: evidence.binding.clone(),
                member: evidence.proofs[0].member.clone(),
            }
            .digest()
            .expect("forged member digest"),
        );
        assert!(
            verify_compact_terminal_evidence_v2(CompactTerminalEvidenceVerificationV2 {
                root: &root,
                configuration_identity: identity,
                logical_time: compact_time(20),
                binding,
                registration,
                admission_provenance: &valid_provenance,
                committing_authority: &authority,
                evidence: &evidence,
            })
            .is_err()
        );

        let (_, _, _, _, _, _, _, provenance, _, mut wrong_authority) =
            compact_v2_fixture(MAX_MEMBERS);
        wrong_authority.binding.authority_fence += 1;
        let executor_leaf = SigningKey::from_bytes((&[0x45; 32]).into()).expect("executor leaf");
        let wrong_binding = wrong_authority.binding.clone();
        for proof in &mut wrong_authority.proofs {
            proof.signature = sign_digest(
                &executor_leaf,
                RosterCompactTerminalMemberSigningInputV2 {
                    binding: wrong_binding.clone(),
                    member: proof.member.clone(),
                }
                .digest()
                .expect("wrong authority member digest"),
            );
        }
        assert!(
            verify_compact_terminal_evidence_v2(CompactTerminalEvidenceVerificationV2 {
                root: &root,
                configuration_identity: identity,
                logical_time: compact_time(20),
                binding,
                registration,
                admission_provenance: &provenance,
                committing_authority: &authority,
                evidence: &wrong_authority,
            })
            .is_err()
        );

        let (_, _, _, _, _, _, _, provenance, _, mut evidence) = compact_v2_fixture(MAX_MEMBERS);
        evidence.proofs[0].signature = sign_digest(
            &SigningKey::from_bytes((&[0x45; 32]).into()).expect("executor leaf"),
            [0x5a; 32],
        );
        assert!(
            verify_compact_terminal_evidence_v2(CompactTerminalEvidenceVerificationV2 {
                root: &root,
                configuration_identity: identity,
                logical_time: compact_time(20),
                binding,
                registration,
                admission_provenance: &provenance,
                committing_authority: &authority,
                evidence: &evidence,
            })
            .is_err()
        );
        assert!(terminal.validate_for(&admission).is_ok());
    }

    #[test]
    fn compact_v2_terminal_allows_a_higher_current_fence_without_rewriting_admission() {
        use crate::fenced_mutation_roster_executor::AuthorityLeaseMetadata;

        let (
            root,
            identity,
            admission,
            binding,
            original_authority,
            registration,
            ingress,
            provenance,
            terminal,
            _,
        ) = compact_v2_fixture(1);
        let successor = AuthorityBinding::from_consensus_parts(
            admission.scope().digest(),
            admission.key().clone(),
            admission.logical_owner().clone(),
            FenceToken::new(original_authority.fence().get() + 1),
            AuthorityLeaseMetadata::new(
                original_authority.credential_id() + 1,
                admission.expected_generation(),
                compact_time(21),
                compact_time(91),
            ),
        )
        .expect("successor authority");
        assert!(
            verify_compact_admission_provenance_v2(CompactAdmissionProvenanceVerificationV2 {
                root: &root,
                configuration_identity: identity,
                binding,
                admission: &admission,
                original_authority: &successor,
                ingress: &ingress,
                provenance: &provenance,
            })
            .is_err()
        );

        let root_key = SigningKey::from_bytes((&[0x41; 32]).into()).expect("root signing key");
        let executor_leaf = SigningKey::from_bytes((&[0x45; 32]).into()).expect("executor leaf");
        let terminal_binding = RosterCompactTerminalEvidenceBindingV2::for_terminal(
            identity,
            binding,
            registration,
            &provenance,
            &admission,
            &successor,
            &terminal,
            [0x4d; 32],
        )
        .expect("successor terminal binding");
        let evidence_commitment =
            roster_executor_evidence_commitment(&vec![0x4c; MAX_EXECUTOR_PROOF_EVIDENCE_BYTES]);
        let proofs = admission
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
                    proof_epoch: 23,
                    provider_operation: RosterProviderOperationV1::Execute,
                    outcome: RosterProviderOutcomeV1::AppliedExecuted,
                    evidence_length: MAX_EXECUTOR_PROOF_EVIDENCE_BYTES as u16,
                    evidence_commitment,
                    stable_proof_commitment: *stable_proof_commitment,
                };
                let signature = sign_digest(
                    &executor_leaf,
                    RosterCompactTerminalMemberSigningInputV2 {
                        binding: terminal_binding.clone(),
                        member: member.clone(),
                    }
                    .digest()
                    .expect("successor member digest"),
                );
                let provider_certificate = compact_certificate(
                    &root,
                    &root_key,
                    &executor_leaf,
                    RosterAttestationCertificateRoleV1::Provider,
                    identity,
                    admission.scope().digest(),
                    [0x4e; 32],
                );
                let provider = RosterAttestationLeafCertificateV1::issue_from_signed_parts(
                    &root,
                    provider_certificate.clone(),
                )
                .expect("provider certificate");
                RosterCompactTerminalMemberProofPartsV2 {
                    provider_signature: sign_digest(
                        &executor_leaf,
                        provider_receipt_compact_digest(&terminal_binding, &member, &provider)
                            .expect("provider digest"),
                    ),
                    provider_certificate,
                    member,
                    signature,
                }
            })
            .collect();
        let certificate = compact_certificate(
            &root,
            &root_key,
            &executor_leaf,
            RosterAttestationCertificateRoleV1::Executor,
            identity,
            admission.scope().digest(),
            [0x4d; 32],
        );
        let successor_evidence = RosterCompactTerminalEvidenceV2::issue_from_signed_parts(
            &root,
            certificate,
            &terminal_binding,
            proofs,
        )
        .expect("successor evidence");
        verify_compact_terminal_evidence_v2(CompactTerminalEvidenceVerificationV2 {
            root: &root,
            configuration_identity: identity,
            logical_time: compact_time(22),
            binding,
            registration,
            admission_provenance: &provenance,
            committing_authority: &successor,
            evidence: &successor_evidence,
        })
        .expect("successor terminal evidence retains original provenance");
    }
}
