//! Atomic, single-record lease-and-mutation transitions.
//!
//! A fenced transition combines exactly one lease acquire or renewal with
//! exactly one mutation of the lease's record. Consensus-backed stores commit
//! the pair at one log position; weaker backends keep the capability disabled.

use std::{fmt, time::Duration};

use opc_types::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    checked_session_deadline,
    error::StoreError,
    lease::LeaseGuard,
    model::{FenceToken, Generation, OwnerId, SessionKey},
    record::StoredSessionRecord,
    ttl::{
        validate_session_ttl, validate_stored_record_expiry_at,
        validate_stored_record_expiry_profile,
    },
};

/// Fixed width of a caller-retained fenced-transition request identity.
pub const FENCED_TRANSITION_REQUEST_ID_BYTES: usize = 16;

/// Maximum permanent ID/body receipt bindings retained for one storage
/// consensus identity.
///
/// This protocol bound includes both full exact-result receipts and their
/// permanent digest tombstones. Once it is reached, no new fenced-transition
/// request ID can be durably bound for that identity.
pub const FENCED_TRANSITION_MAX_HISTORY_ENTRIES: usize = 4_096;

/// Canonical store-side contract implemented by this primitive.
pub const FENCED_TRANSITION_SCHEMA_V1: u16 = 1;

/// Schema for the non-absorbing, epoch-fenced transition receipt history.
///
/// V2 is intentionally a distinct protocol from V1. In particular, V2
/// request identities are 56-byte self-authenticating values and must never
/// be stored in, truncated to, or compared as the V1 16-byte namespace.
pub const FENCED_TRANSITION_SCHEMA_V2: u16 = 2;

/// Maximum physical V2 receipt rows retained for one active history epoch.
pub const FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES: usize = 131_072;

/// Number of V2 bindings an implementation must support operationally before
/// it may need to reclaim a retired epoch.
pub const FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET: usize = 100_000;

/// Number of obsolete V2 history entries reclaimed in one bounded batch.
pub const FENCED_TRANSITION_V2_RECLAIM_BATCH: usize = 1_024;

/// Fixed width of a complete V2 request identity.
pub const FENCED_TRANSITION_V2_REQUEST_ID_BYTES: usize = 8 + 16 + 32;

/// Fixed width of the caller-selected V2 nonce component.
pub const FENCED_TRANSITION_V2_CALLER_NONCE_BYTES: usize = 16;

/// Fixed width of the SHA-256 body-commitment component of a V2 request ID.
pub const FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES: usize = 32;

/// Initial active V2 receipt-history epoch for a freshly activated store.
///
/// Later epochs are valid after durable rotation; this constant specifies
/// only the initial state of a new V2 history.
pub const FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH: u64 = 1;

/// Greatest V2 history epoch representable by every supported durable store.
///
/// SQLite persists epochs in a signed `INTEGER`, so V2 reserves values above
/// this bound rather than allowing a request that a compatible store cannot
/// durably represent.
pub const FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH: u64 = i64::MAX as u64;

/// Greatest V2 durable history-state generation representable by every store.
///
/// SQLite persists the lifecycle CAS generation in a signed `INTEGER`, so the
/// public fixed-width state wire rejects larger `u64` values rather than
/// materializing a token that cannot be durably observed or advanced.
pub const FENCED_TRANSITION_V2_MAX_DURABLE_GENERATION: u64 = i64::MAX as u64;

/// Maximum bytes in one persisted V2 receipt response envelope.
///
/// This includes the fixed response codec metadata in addition to the maximum
/// typed transition outcome; a compatible implementation must reject a larger
/// envelope before storing or hashing it.
pub const FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES: usize =
    FENCED_TRANSITION_MAX_OUTCOME_BYTES + 1_024;

/// Exact encrypted-record payload capacity admitted by every V2 voter.
///
/// This is distinct from a backend's general `max_value_bytes`: V2 command
/// admission and every follower's envelope validation must use this fixed
/// value so a leader cannot propose a record that another activated voter
/// rejects. Backends with a different local capacity must not advertise V2.
pub const FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES: usize = 1_048_576;

/// Largest `actual` value permitted in V2's `PayloadTooLarge` receipt error.
///
/// The receipt codec uses a `u64`, but the public error type currently uses a
/// `usize`. Fixing this wire-domain bound to `u32::MAX` prevents a receipt
/// accepted by a 64-bit voter from being rejected by a 32-bit voter before it
/// reaches the typed error representation.
pub const FENCED_TRANSITION_V2_MAX_PAYLOAD_TOO_LARGE_ACTUAL_BYTES: u64 = u32::MAX as u64;

/// Lowest Unix second permitted in a V2 timestamp (`-9999-01-01T00:00:00Z`).
///
/// V2 fixes this range independently of optional `time` crate features so
/// every voter accepts exactly the same command and receipt timestamps.
pub const FENCED_TRANSITION_V2_MIN_TIMESTAMP_UNIX_SECONDS: i64 = -377_705_116_800;

/// Highest Unix second permitted in a V2 timestamp (`9999-12-31T23:59:59Z`).
pub const FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS: i64 = 253_402_300_799;

/// Revision of V2's fixed persisted receipt-response codec.
pub const FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_REVISION: u8 = 1;

/// Eight-byte magic prefix of V2's fixed persisted receipt-response codec.
pub const FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_MAGIC: [u8; 8] = *b"OPCFV2R1";

/// Frozen schema descriptor for V2's persisted receipt-response codec.
///
/// The result is an exact, non-Serde binary envelope. Unknown tags, a
/// noncanonical timestamp, an oversized length, or trailing bytes are
/// invalid rather than a request to reinterpret stored receipt data.
pub const FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_SCHEMA_DESCRIPTOR: &str = concat!(
    "codec=OPCFV2R1;revision=1;framing=big-endian,bytes:length-u64be,",
    "timestamp:unix-secs-i64be+nanos-u32be;",
    "envelope=magic:bytes8|revision:u8|result|sequence:u64be|entry-digest:bytes32|",
    "logical-time:timestamp|raft-log-index:u64be;",
    "success(tag=1)=lease(key(tenant:utf8-len,nf-kind:utf8-len,key-type:u8[1=subscriber-context,",
    "2=pdu-session,3=teid-mapping,4=pfcp-seid,5=handover-transaction,6=other+utf8-len],",
    "stable-id:bytes-len),owner:utf8-len,fence:u64be,acquired-at:timestamp,",
    "expires-at:timestamp,credential-id:u64be),generation:u64be,",
    "mutation:u8[1=created,2=updated,3=deleted,4=ttl-refreshed+timestamp],recorded-at:timestamp;",
    "errors=16:topology-authority-revoked,17:not-found,18:stale-fence,19:cas-conflict,",
    "20:invalid-session-ttl,21:invalid-record-expiry,22:lease-held,23:lease-expired,",
    "24:payload-too-large(actual:u64be,max:u64be;max=validation.max-record-payload-bytes,",
    "validation.max-record-payload-bytes<actual<=validation.max-payload-too-large-actual-bytes),",
    "25:storage-exhausted;",
    "max-bytes=17408"
);

/// Revision of V2's shared request, follower-apply, and receipt-decode
/// validation rules.
pub const FENCED_TRANSITION_V2_VALIDATION_SCHEMA_REVISION: u16 = 1;

/// Fixed V2 numeric validation inputs, in the descriptor's declared order.
///
/// These are represented as `u64` rather than platform-sized integers before
/// they are included in the V2 profile. This prevents a compatible build from
/// silently changing an admission or decoder limit through a `usize` change.
pub const FENCED_TRANSITION_V2_VALIDATION_PROFILE_INPUTS: [u64; 18] = [
    crate::ttl::MAX_SESSION_TTL.as_secs(),
    crate::ttl::MAX_SESSION_TTL.subsec_nanos() as u64,
    crate::ttl::MAX_RECORD_EXPIRY_CLOCK_SKEW.as_secs(),
    crate::ttl::MAX_RECORD_EXPIRY_CLOCK_SKEW.subsec_nanos() as u64,
    128, // TenantId's fixed V2 slug bound.
    64,  // NetworkFunctionKind's fixed V2 slug bound.
    crate::model::STABLE_ID_MIN_BYTES as u64,
    crate::model::STABLE_ID_MAX_BYTES as u64,
    crate::model::SESSION_KEY_TYPE_MAX_BYTES as u64,
    crate::model::OWNER_ID_MAX_BYTES as u64,
    crate::model::STATE_TYPE_MAX_BYTES as u64,
    FENCED_TRANSITION_V2_MIN_TIMESTAMP_UNIX_SECONDS as u64,
    FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS as u64,
    999_999_999, // Largest canonical timestamp nanosecond component.
    1,           // Nonzero lease fence and credential minimum.
    FENCED_TRANSITION_V2_MAX_DURABLE_GENERATION, // SQLite-portable sequence, generation, and epoch horizon.
    FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES as u64,
    FENCED_TRANSITION_V2_MAX_PAYLOAD_TOO_LARGE_ACTUAL_BYTES,
];

/// Frozen V2 validation and fixed-response decoder contract.
///
/// Numeric values are supplied, in order, by
/// [`FENCED_TRANSITION_V2_VALIDATION_PROFILE_INPUTS`] and hashed separately
/// from this descriptor. V2's record payload capacity is a fixed protocol
/// input, not a process-local backend capability.
pub const FENCED_TRANSITION_V2_VALIDATION_SCHEMA_DESCRIPTOR: &str = concat!(
    "validation-schema=1;inputs=",
    "max-session-ttl-secs,max-session-ttl-nanos,record-expiry-skew-secs,",
    "record-expiry-skew-nanos,tenant-slug-max,nf-kind-slug-max,stable-id-min,",
    "stable-id-max,custom-key-type-max,owner-max,state-type-max,timestamp-min-secs,",
    "timestamp-max-secs,timestamp-nanos-max,lease-nonzero-min,durable-counter-max,",
    "max-record-payload-bytes,max-payload-too-large-actual-bytes;",
    "request=full-id-self-auth-before-history;ttl=positive,<=max-session-ttl;",
    "tenant,nf-kind=nonempty-lowercase-ascii-slug,no-edge-hyphen,respective-max;",
    "stable-id=bytes[min,max];owner,state-type=nonempty-utf8,respective-max;",
    "custom-key-type=nonempty-utf8,<=max,reserved-well-known-spellings-rejected;",
    "lease-guard=fence>=nonzero-min,credential>=nonzero-min,expires>=acquired;",
    "acquire-fence=expected+1,nonwrapping-nonzero;generation=exact-create-one-or-nonwrapping-successor,<=durable-counter-max;",
    "record-expiry=ephemeral-requires-finite,finite<=logical-time+max-session-ttl+skew,",
    "create-update-expiry>logical-time;refresh=renew-only,positive,<=max-session-ttl;",
    "follower-apply=validate-at-leader-logical-time,record-payload=canonical-envelope-v1+matching-aad,",
    "payload-capacity=exact-max-record-payload-bytes,local-backend-mismatch-disables-v2;",
    "response-decode=length<=receipt-response-max,exact-magic-revision-tags-and-framing,",
    "payload-too-large=max:exact-max-record-payload-bytes,actual:max<actual<=max-payload-too-large-actual-bytes,",
    "timestamp=secs[timestamp-min-secs,timestamp-max-secs]+nanos<=timestamp-nanos-max,",
    "derived-deadlines=lease-and-refresh(logical-time+ttl)must-satisfy-timestamp-range,",
    "key-and-guard=same-rules,",
    "sequence>0,raft-log-index>0,success=outcome-validated,no-trailing-bytes"
);

/// Revision of the V2 command transport and durable-log constraints.
pub const FENCED_TRANSITION_V2_COMMAND_TRANSPORT_SCHEMA_REVISION: u16 = 1;

/// Consensus envelope schema required by V2 command transport.
pub const FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION: u16 = 1;

/// Minimum bounded Postcard RPC payload capacity required by V2.
pub const FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;

/// Minimum durable JSON consensus-log entry capacity required by V2.
pub const FENCED_TRANSITION_V2_MIN_DURABLE_LOG_ENTRY_BYTES: usize = 16 * 1024 * 1024;

/// Minimum command transport capacities required before a backend may offer
/// V2, in the command-transport descriptor's declared order.
pub const FENCED_TRANSITION_V2_COMMAND_TRANSPORT_PROFILE_INPUTS: [u64; 3] = [
    FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION as u64,
    FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES as u64,
    FENCED_TRANSITION_V2_MIN_DURABLE_LOG_ENTRY_BYTES as u64,
];

/// Frozen V2 command transport and durable-log codec contract.
///
/// The V2 capability gate must reject a local transport or durable log whose
/// active limits are below these fixed protocol minima. They are profile
/// inputs because nested V2 DTOs are decoded before their follower validation.
pub const FENCED_TRANSITION_V2_COMMAND_TRANSPORT_SCHEMA_DESCRIPTOR: &str = concat!(
    "command-transport-schema=1;inputs=consensus-schema-version,",
    "minimum-rpc-payload-bytes,minimum-durable-log-entry-bytes;",
    "rpc=postcard-1.1.3,serialized-size+to-slice,take-from-bytes,no-trailing-bytes,",
    "payload<=minimum-rpc-payload-bytes;",
    "durable-log=serde-json,exact-command-wire-schema,no-trailing-data,",
    "entry<=minimum-durable-log-entry-bytes;",
    "admission=local-capacity-below-minimum-disables-v2"
);

/// Revision of V2's mandatory encrypted session-record envelope contract.
pub const FENCED_TRANSITION_V2_RECORD_ENVELOPE_SCHEMA_REVISION: u16 = 1;

/// Frozen parser and AAD contract for `SessionPayloadEncoding::EnvelopeV1`.
///
/// This is intentionally explicit because nested payload deserialization
/// parses it before V2 follower validation. The profile therefore changes if
/// any accepted envelope/AAD language changes.
pub const FENCED_TRANSITION_V2_RECORD_ENVELOPE_SCHEMA_DESCRIPTOR: &str = concat!(
    "record-envelope-schema=1;follower-record-encoding=envelope-v1-only;",
    "envelope=magic:OPCE:bytes4,version:u16be=1,algorithm:u16be,",
    "key-id-len:u16be,nonce-len:u16be,aad-len:u32be,header-bytes=16,",
    "key-id:nonempty-ascii-alnum-or--_.:/,max=512,no-edge-whitespace,",
    "algorithm[1=aes-256-gcm-siv:nonce=12,2=remote-seal:nonce=0],",
    "ciphertext-and-tag>=16,reencode-exact;",
    "aad=canonical-json,no-unknown-fields,field-order=tenant,purpose,version,key_id,metadata,",
    "purpose=session,version=1,metadata=tagged-kind:session,",
    "session-metadata-field-order=nf_kind,session_key_digest,state_type,generation,fence,backend_namespace,",
    "session-metadata-strings=no-nul;",
    "record-binding=tenant,nf-kind,state-type,generation,fence;",
    "payload=nonempty-envelope,bytes<=max-record-payload-bytes"
);

/// Exact V2 outcome-retention duration inputs, ordered as seconds then
/// nanoseconds. Both values participate in the advertised profile because
/// they determine receipt retention deadlines and binding bytes.
pub const FENCED_TRANSITION_V2_RETENTION_PROFILE_INPUTS: [u64; 2] = [
    FENCED_TRANSITION_OUTCOME_RETENTION.as_secs(),
    FENCED_TRANSITION_OUTCOME_RETENTION.subsec_nanos() as u64,
];

/// Revision of V2's backend-neutral persisted receipt-history schema.
pub const FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_REVISION: u16 = 1;

/// Frozen backend-neutral schema for V2's durable receipt history.
///
/// This describes protocol state rather than a particular database's DDL. A
/// durable implementation may choose its storage engine, but it must preserve
/// these identities, fields, bounds, and lifecycle ordering to advertise V2.
pub const FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_DESCRIPTOR: &str = concat!(
    "history-format=3;revision=1;scope=one-history-singleton-per-storage-identity;",
    "singleton=immutable-profile-digest:bytes32,storage-configuration-epoch:u64be,",
    "active-epoch:optional-u64,retired-through-epoch:optional-u64,generation:u64be<=durable-counter-max,",
    "bound-entry-count:u64be,reclaim-epoch:optional-u64,reclaim-cursor-ordinal:optional-u64,",
    "reclaim-remaining:u64be,reclaimed-entries:u64be;",
    "receipt=full-id:bytes56-primary-identity,history-epoch:u64be,ordinal:u64be,",
    "storage-configuration-epoch:u64be,payload-digest:bytes32,retained-until:ascii-rfc3339,",
    "binding-digest:bytes32,response:optional-exact-codec-bytes,response-digest:bytes32;",
    "activation-certificate=storage-identity,scope-identity,voter-set-digest:bytes32,",
    "immutable-profile-digest:bytes32;",
    "capacity=active-epoch-receipts<=131072;index=history-epoch-ascending,ordinal-ascending,",
    "unique(history-epoch,ordinal);reclaim=retire-floor-before-delete,",
    "ordered(history-epoch,ordinal)-ascending,batch<=1024,no-active-during-reclaim,",
    "open-immediate-successor-only-after-final-batch"
);

/// Revision of V2's fixed error and status meanings covered by its profile.
pub const FENCED_TRANSITION_V2_ERROR_STATUS_REVISION: u16 = 2;

/// Frozen schema descriptor for V2's profile, outer identity, and body bytes.
///
/// This descriptor is deliberately descriptive rather than executable: the
/// byte-level encoder below is the normative implementation. It is included
/// in [`fenced_transition_v2_profile_digest`] so an implementation cannot
/// advertise this profile while using a different field ordering, enum
/// representation, or outer-ID derivation.
pub const FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR: &str = concat!(
    "profile-schema=1;",
    "full-id=epoch:u64be|nonce:bytes16|commitment:sha256;",
    "request-wire=materialize-representable-body;ingress=validate-commitment-before-semantic-validation;",
    "outer-id=sha256(domain=openpacketcore/session-consensus/fenced-transition-v2/outer-id\\0,full-id:56)[0..16];",
    "commitment=sha256(domain=openpacketcore/fenced-transition/v2/request-commitment\\0",
    ",schema:u16be,epoch:u64be,nonce:bytes16,body-len:u64be,body);",
    "history-epoch=nonzero-u64,range:1..=i64-max;body=version:u8=1|lease|mutation;",
    "history-state-wire=active-epoch:optional-u64,retired-through:optional-u64,",
    "reclaim-epoch:optional-u64,reclaim-remaining:u64,generation:u64<=i64-max,bound-entries:u64,",
    "reclaimed-entries:u64;",
    "framing=tags:u8,integers:big-endian,bytes:length-u64be,",
    "duration:secs-u64be+nanos-u32be,timestamp:unix-secs-i64be+nanos-u32be,",
    "optional-timestamp:tag-u8+timestamp;",
    "lease=acquire(tag=1,key,owner,fence,ttl)|renew(tag=2,guard,ttl);",
    "mutation=create(tag=17,record)|update(tag=18,generation,record)|",
    "delete(tag=19,generation)|refresh-ttl(tag=20,generation,ttl);",
    "key=tag33,tenant,nf-kind,key-type-tag+custom-key-type,stable-id;",
    "guard=tag34,key,owner,fence,acquired-at,expires-at,credential-id;",
    "record=tag35,key,generation,owner,fence,state-class-tag,state-type,",
    "optional-expiry,payload-encoding-tag+payload-bytes;",
    "canonical-enum-tags=lease[acquire:1,renew:2],mutation[create:17,update:18,delete:19,",
    "refresh-ttl:20],key[subscriber-context:1,pdu-session:2,teid-mapping:3,pfcp-seid:4,",
    "handover-transaction:5,other:6],state-class[authoritative-session:1,dataplane-lookup:2,",
    "replicated-dr:3,telemetry-derived:4,ephemeral-procedure:5],payload-encoding[plaintext:1,",
    "legacy-plaintext:2,envelope-v1:3,unclassified:4];",
    "command-wire-nested-serde=request=id(epoch:u64,nonce:bytes16,commitment:bytes32),lease,mutation;",
    "lease-postcard[acquire:0,renew:1],mutation-postcard[create:0,update:1,delete:2,refresh-ttl:3];",
    "session-key=tenant,nf-kind,key-type-string,stable-id-bytes;",
    "lease-guard=key,owner,fence,acquired-at,expires-at,credential-id;",
    "stored-record=key,generation,owner,fence,state-class,state-type,expires-at,payload;",
    "state-class-postcard[authoritative-session:0,dataplane-lookup:1,replicated-dr:2,",
    "telemetry-derived:3,ephemeral-procedure:4];",
    "payload=bytes,encoding;payload-encoding-postcard[plaintext:0,legacy-plaintext:1,",
    "envelope-v1:2,unclassified:3];timestamp=canonical-rfc3339-string;",
    "duration=serde-struct(secs:u64,nanos:u32);",
    "receipt-payload=sha256(domain=openpacketcore/session-consensus/fenced-transition-v2/payload/v1\\0,",
    "schema:u16be,profile-digest:bytes32,storage-cluster:bytes32,storage-config:bytes32,",
    "storage-epoch:u64be,full-id:bytes56);",
    "receipt-binding=sha256(domain=openpacketcore/session-consensus/fenced-transition-v2-receipt-binding/v1\\0,",
    "schema:u16be,profile-digest:bytes32,storage-cluster:bytes32,storage-config:bytes32,",
    "storage-epoch:u64be,full-id:bytes56,history-epoch:u64be,ordinal:u64be,payload:bytes32,",
    "retained-until-ascii:length-u64be+bytes);",
    "receipt-response=sha256(domain=openpacketcore/session-consensus/fenced-transition-v2-receipt-response/v1\\0,",
    "binding:bytes32,response:length-u64be+exact-bytes);",
    "receipt-response-codec=see:FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_SCHEMA_DESCRIPTOR;",
    "validation=see:FENCED_TRANSITION_V2_VALIDATION_SCHEMA_DESCRIPTOR;",
    "command-transport=see:FENCED_TRANSITION_V2_COMMAND_TRANSPORT_SCHEMA_DESCRIPTOR;",
    "record-envelope=see:FENCED_TRANSITION_V2_RECORD_ENVELOPE_SCHEMA_DESCRIPTOR;",
    "outcome-retention=secs-u64be+nanos-u64be;",
    "applied-command-digest=see:SESSION_CONSENSUS_V2_APPLIED_DIGEST_SCHEMA_DESCRIPTOR;",
    "replicated-command-wire=see:SESSION_CONSENSUS_V2_COMMAND_WIRE_SCHEMA_DESCRIPTOR;",
    "persisted-history=see:FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_DESCRIPTOR"
);

const FENCED_TRANSITION_V2_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/fenced-transition/v2/request-commitment\0";
const FENCED_TRANSITION_V2_OUTER_REQUEST_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/fenced-transition-v2/outer-id\0";

/// Exact atomic-transition capability advertised by a compatible store.
///
/// This is deliberately versioned rather than inferred from independent CAS,
/// fencing, TTL, or batch flags: composing those operations does not provide
/// the single linearization point required by this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AtomicFencedTransitionCapability {
    /// One exact-key lease acquire/renew and one same-record mutation.
    V1,
    /// V2's epoch-fenced, reclaimable receipt history with the fixed profile
    /// identified by [`fenced_transition_v2_profile_digest`].
    ///
    /// This is not a reinterpretation of `V1`: callers must submit V2
    /// requests and use V2 status/history types when this variant is offered.
    V2,
}

/// Exact-result recovery window for a committed fenced transition.
///
/// The durable request/body binding remains for the consensus identity's
/// lifetime, including snapshots. The exact result is available for this
/// fixed window after its committed logical time. Once the window expires,
/// replay remains closed and status returns `Expired` instead of applying the
/// request again.
pub const FENCED_TRANSITION_OUTCOME_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum canonical JSON size accepted for one serialized transition result.
///
/// Results contain only one bounded key-bearing lease credential and scalar
/// mutation metadata; they never echo a record payload.
pub const FENCED_TRANSITION_MAX_OUTCOME_BYTES: usize = 16 * 1024;

const INVALID_TRANSITION_KEY: &str = "fenced_transition_key_mismatch";
const INVALID_TRANSITION_FENCE: &str = "fenced_transition_fence_mismatch";
const INVALID_TRANSITION_OWNER: &str = "fenced_transition_owner_mismatch";
const INVALID_TRANSITION_GENERATION: &str = "fenced_transition_generation_invalid";
const INVALID_TRANSITION_REFRESH_ACQUIRE: &str = "fenced_transition_refresh_acquire_invalid";
const INVALID_TRANSITION_OUTCOME: &str = "fenced_transition_outcome_invalid";
const INVALID_TRANSITION_REQUEST_ID: &str = "fenced_transition_request_id_invalid";
const INVALID_TRANSITION_V2_HISTORY_EPOCH: &str = "fenced_transition_v2_history_epoch_invalid";

/// Caller-generated identity retained unchanged across submission and status.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FencedTransitionRequestId([u8; FENCED_TRANSITION_REQUEST_ID_BYTES]);

impl FencedTransitionRequestId {
    /// Generate a new opaque request identity.
    pub fn new() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Reconstruct an identity retained with its exact canonical request.
    pub const fn from_bytes(bytes: [u8; FENCED_TRANSITION_REQUEST_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width persisted representation.
    pub const fn as_bytes(&self) -> &[u8; FENCED_TRANSITION_REQUEST_ID_BYTES] {
        &self.0
    }

    /// Borrow the fixed-width opaque request identity.
    pub const fn opaque_bytes(&self) -> &[u8; FENCED_TRANSITION_REQUEST_ID_BYTES] {
        self.as_bytes()
    }
}

impl Default for FencedTransitionRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FencedTransitionRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionRequestId(<redacted>)")
    }
}

/// A nonzero, monotonically advancing namespace for V2 request history.
///
/// An epoch is chosen by the durable history owner, not by a storage key. An
/// epoch at or below `retired_through` is permanently closed and a request in
/// it must return `StoreError::FencedTransitionHistoryEpochRetired` (or V2
/// status `Retired`) without applying its lease or mutation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct FencedTransitionV2HistoryEpoch(u64);

impl FencedTransitionV2HistoryEpoch {
    /// Construct a history epoch representable by every V2 durable store.
    pub fn new(epoch: u64) -> Result<Self, StoreError> {
        if !(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH..=FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH)
            .contains(&epoch)
        {
            return Err(StoreError::InvalidKey(
                INVALID_TRANSITION_V2_HISTORY_EPOCH.into(),
            ));
        }
        Ok(Self(epoch))
    }

    /// Return the persisted epoch number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for FencedTransitionV2HistoryEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionV2HistoryEpoch(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for FencedTransitionV2HistoryEpoch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Caller-retained nonce for a V2 request identity.
///
/// The nonce is stable across retries. It is committed into the V2 ID along
/// with the epoch and canonical request body, so it is never a standalone
/// idempotency key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FencedTransitionV2CallerNonce([u8; FENCED_TRANSITION_V2_CALLER_NONCE_BYTES]);

impl FencedTransitionV2CallerNonce {
    /// Generate a fresh caller nonce.
    pub fn new() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Reconstruct a caller nonce retained for a stable retry.
    pub const fn from_bytes(bytes: [u8; FENCED_TRANSITION_V2_CALLER_NONCE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width persisted nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; FENCED_TRANSITION_V2_CALLER_NONCE_BYTES] {
        &self.0
    }
}

impl Default for FencedTransitionV2CallerNonce {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FencedTransitionV2CallerNonce {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionV2CallerNonce(<redacted>)")
    }
}

/// Full self-authenticating V2 request identity.
///
/// The 56-byte value is the concatenation of a nonzero history epoch, a
/// caller nonce, and a full SHA-256 commitment to that exact canonical V2
/// body. Implementations must retain and compare all 56 bytes; truncating it
/// or using V1's 16-byte receipt namespace loses V2's conflict guarantee.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedTransitionV2RequestId {
    epoch: FencedTransitionV2HistoryEpoch,
    nonce: FencedTransitionV2CallerNonce,
    body_commitment: [u8; FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES],
}

impl FencedTransitionV2RequestId {
    /// Reconstruct a complete identity retained with a serialized V2 request.
    pub const fn from_parts(
        epoch: FencedTransitionV2HistoryEpoch,
        nonce: FencedTransitionV2CallerNonce,
        body_commitment: [u8; FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES],
    ) -> Self {
        Self {
            epoch,
            nonce,
            body_commitment,
        }
    }

    /// The durable V2 history epoch selected for this request.
    pub const fn epoch(&self) -> FencedTransitionV2HistoryEpoch {
        self.epoch
    }

    /// The caller-retained nonce selected for this request.
    pub const fn nonce(&self) -> FencedTransitionV2CallerNonce {
        self.nonce
    }

    /// Full SHA-256 commitment to the canonical request body.
    pub const fn body_commitment(&self) -> &[u8; FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES] {
        &self.body_commitment
    }

    /// Return the complete persisted identity without truncation.
    pub fn to_bytes(&self) -> [u8; FENCED_TRANSITION_V2_REQUEST_ID_BYTES] {
        let mut bytes = [0; FENCED_TRANSITION_V2_REQUEST_ID_BYTES];
        bytes[..8].copy_from_slice(&self.epoch.get().to_be_bytes());
        bytes[8..24].copy_from_slice(self.nonce.as_bytes());
        bytes[24..].copy_from_slice(&self.body_commitment);
        bytes
    }
}

impl fmt::Debug for FencedTransitionV2RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionV2RequestId(<redacted>)")
    }
}

/// Derive the fixed-width consensus-envelope identity from a complete V2 ID.
///
/// The first 16 bytes of a SHA-256 digest over the frozen domain and all 56
/// bytes of the V2 ID are used only for the generic outer envelope. Durable
/// V2 receipt history must continue to use the complete ID, never this
/// truncated derivative.
pub(crate) fn fenced_transition_v2_outer_request_id(
    request_id: FencedTransitionV2RequestId,
) -> [u8; FENCED_TRANSITION_REQUEST_ID_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(FENCED_TRANSITION_V2_OUTER_REQUEST_ID_DOMAIN);
    hasher.update(request_id.to_bytes());
    let digest: [u8; FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES] = hasher.finalize().into();
    digest[..FENCED_TRANSITION_REQUEST_ID_BYTES]
        .try_into()
        .expect("SHA-256 output has a 16-byte prefix")
}

/// Lease action committed together with one record mutation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FencedTransitionLease {
    /// Acquire a new credential under the exact previously observed fence.
    ///
    /// The committed fence is `expected_fence + 1`. This deterministic target
    /// lets a protected record bind that fence in its AEAD AAD before the
    /// request crosses the consensus boundary. A different persisted fence is
    /// a no-effect stale-fence rejection.
    Acquire {
        /// Exact record/lease key.
        key: SessionKey,
        /// Owner receiving the new credential.
        owner: OwnerId,
        /// Exact current fence, or zero for a key with no fence history.
        expected_fence: FenceToken,
        /// Bounded lease lifetime from committed admission time.
        ttl: Duration,
    },
    /// Renew one exact, unexpired lease credential without changing its fence.
    Renew {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Bounded renewed lifetime from committed admission time.
        ttl: Duration,
    },
}

impl FencedTransitionLease {
    /// Build a deterministic acquire action.
    pub fn acquire(
        key: SessionKey,
        owner: OwnerId,
        expected_fence: FenceToken,
        ttl: Duration,
    ) -> Result<Self, StoreError> {
        let action = Self::Acquire {
            key,
            owner,
            expected_fence,
            ttl,
        };
        action.validate()?;
        Ok(action)
    }

    /// Build a renewal action for an exact credential.
    pub fn renew(lease: LeaseGuard, ttl: Duration) -> Result<Self, StoreError> {
        let action = Self::Renew { lease, ttl };
        action.validate()?;
        Ok(action)
    }

    /// Exact key shared by the lease and record mutation.
    pub fn key(&self) -> &SessionKey {
        match self {
            Self::Acquire { key, .. } => key,
            Self::Renew { lease, .. } => lease.key(),
        }
    }

    /// Exact owner authorized by the transition.
    pub fn owner(&self) -> &OwnerId {
        match self {
            Self::Acquire { owner, .. } => owner,
            Self::Renew { lease, .. } => lease.owner(),
        }
    }

    /// Fence that a successful transition commits and returns.
    pub fn committed_fence(&self) -> Result<FenceToken, StoreError> {
        match self {
            Self::Acquire { expected_fence, .. } => expected_fence
                .get()
                .checked_add(1)
                .filter(|fence| *fence != 0)
                .map(FenceToken::new)
                .ok_or_else(|| StoreError::InvalidKey(INVALID_TRANSITION_FENCE.into())),
            Self::Renew { lease, .. } => Ok(lease.fence()),
        }
    }

    /// Requested lease lifetime.
    pub const fn ttl(&self) -> Duration {
        match self {
            Self::Acquire { ttl, .. } | Self::Renew { ttl, .. } => *ttl,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        validate_positive_ttl(self.ttl())?;
        if let Self::Renew { lease, .. } = self {
            lease.validate_profile()?;
        }
        let _ = self.committed_fence()?;
        Ok(())
    }

    pub(crate) fn validate_at(&self, logical_time: Timestamp) -> Result<(), StoreError> {
        self.validate()?;
        if let Self::Renew { lease, .. } = self {
            if lease.expires_at() <= logical_time {
                return Err(StoreError::LeaseExpired);
            }
        }
        let _ = checked_session_deadline(logical_time, self.ttl())?;
        Ok(())
    }
}

impl fmt::Debug for FencedTransitionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self {
            Self::Acquire { .. } => "Acquire",
            Self::Renew { .. } => "Renew",
        };
        formatter
            .debug_struct("FencedTransitionLease")
            .field("action", &action)
            .finish_non_exhaustive()
    }
}

/// One same-record mutation committed with the lease action.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FencedTransitionMutation {
    /// Create an absent record at generation one.
    Create {
        /// Complete record to install.
        record: Box<StoredSessionRecord>,
    },
    /// Replace an existing record at the exact successor generation.
    Update {
        /// Exact current generation required for admission.
        expected_generation: Generation,
        /// Complete successor record to install.
        record: Box<StoredSessionRecord>,
    },
    /// Delete an existing record only at the exact generation.
    Delete {
        /// Exact current generation required for admission.
        expected_generation: Generation,
    },
    /// Replace an existing record's TTL only at the exact generation.
    RefreshTtl {
        /// Exact current generation required for admission.
        expected_generation: Generation,
        /// New lifetime measured from committed admission time.
        ttl: Duration,
    },
}

impl FencedTransitionMutation {
    /// Build an absent-record creation.
    pub fn create(record: StoredSessionRecord) -> Self {
        Self::Create {
            record: Box::new(record),
        }
    }

    /// Build an exact-generation replacement.
    pub fn update(expected_generation: Generation, record: StoredSessionRecord) -> Self {
        Self::Update {
            expected_generation,
            record: Box::new(record),
        }
    }

    /// Build an exact-generation deletion.
    pub const fn delete(expected_generation: Generation) -> Self {
        Self::Delete {
            expected_generation,
        }
    }

    /// Build an exact-generation TTL refresh.
    pub fn refresh_ttl(expected_generation: Generation, ttl: Duration) -> Result<Self, StoreError> {
        validate_positive_ttl(ttl)?;
        Ok(Self::RefreshTtl {
            expected_generation,
            ttl,
        })
    }

    /// Expected live record generation, or `None` for create-if-absent.
    pub const fn expected_generation(&self) -> Option<Generation> {
        match self {
            Self::Create { .. } => None,
            Self::Update {
                expected_generation,
                ..
            }
            | Self::Delete {
                expected_generation,
            }
            | Self::RefreshTtl {
                expected_generation,
                ..
            } => Some(*expected_generation),
        }
    }

    /// Replacement record for create/update operations.
    pub fn record(&self) -> Option<&StoredSessionRecord> {
        match self {
            Self::Create { record } | Self::Update { record, .. } => Some(record),
            Self::Delete { .. } | Self::RefreshTtl { .. } => None,
        }
    }

    pub(crate) fn validate_for_lease(
        &self,
        lease: &FencedTransitionLease,
    ) -> Result<(), StoreError> {
        if let Self::RefreshTtl { ttl, .. } = self {
            validate_positive_ttl(*ttl)?;
            if matches!(lease, FencedTransitionLease::Acquire { .. }) {
                return Err(StoreError::InvalidKey(
                    INVALID_TRANSITION_REFRESH_ACQUIRE.into(),
                ));
            }
        }
        let Some(record) = self.record() else {
            return Ok(());
        };
        if &record.key != lease.key() {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_KEY.into()));
        }
        if &record.owner != lease.owner() {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_OWNER.into()));
        }
        if record.fence != lease.committed_fence()? {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_FENCE.into()));
        }
        let expected_new_generation = match self {
            Self::Create { .. } => Generation::new(1),
            Self::Update {
                expected_generation,
                ..
            } => expected_generation
                .next()
                .ok_or_else(|| StoreError::InvalidKey(INVALID_TRANSITION_GENERATION.into()))?,
            Self::Delete { .. } | Self::RefreshTtl { .. } => unreachable!(),
        };
        if record.generation != expected_new_generation {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_GENERATION.into()));
        }
        validate_stored_record_expiry_profile(record)
    }

    pub(crate) fn validate_at(&self, logical_time: Timestamp) -> Result<(), StoreError> {
        match self {
            Self::Create { record } | Self::Update { record, .. } => {
                validate_stored_record_expiry_at(record, logical_time)?;
                if record
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= logical_time)
                {
                    return Err(StoreError::InvalidRecordExpiry);
                }
                Ok(())
            }
            Self::Delete { .. } => Ok(()),
            Self::RefreshTtl { ttl, .. } => {
                validate_positive_ttl(*ttl)?;
                let _ = checked_session_deadline(logical_time, *ttl)?;
                Ok(())
            }
        }
    }
}

impl fmt::Debug for FencedTransitionMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mutation = match self {
            Self::Create { .. } => "Create",
            Self::Update { .. } => "Update",
            Self::Delete { .. } => "Delete",
            Self::RefreshTtl { .. } => "RefreshTtl",
        };
        formatter
            .debug_struct("FencedTransitionMutation")
            .field("mutation", &mutation)
            .finish_non_exhaustive()
    }
}

/// Complete canonical body bound to one stable request identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedTransitionRequest {
    request_id: FencedTransitionRequestId,
    lease: FencedTransitionLease,
    mutation: FencedTransitionMutation,
}

impl FencedTransitionRequest {
    /// Construct and structurally validate one bounded single-record request.
    pub fn new(
        request_id: FencedTransitionRequestId,
        lease: FencedTransitionLease,
        mutation: FencedTransitionMutation,
    ) -> Result<Self, StoreError> {
        let request = Self {
            request_id,
            lease,
            mutation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Stable caller-generated request identity.
    pub const fn request_id(&self) -> FencedTransitionRequestId {
        self.request_id
    }

    /// Lease action committed by this request.
    pub const fn lease(&self) -> &FencedTransitionLease {
        &self.lease
    }

    /// Same-record mutation committed by this request.
    pub const fn mutation(&self) -> &FencedTransitionMutation {
        &self.mutation
    }

    /// Validate time-independent structure before any proposal or provider work.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.request_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_REQUEST_ID.into()));
        }
        self.lease.validate()?;
        self.mutation.validate_for_lease(&self.lease)
    }

    /// Validate time-dependent request constraints at committed logical time.
    pub fn validate_at(&self, logical_time: Timestamp) -> Result<(), StoreError> {
        self.validate()?;
        self.lease.validate_at(logical_time)?;
        self.mutation.validate_at(logical_time)
    }
}

impl fmt::Debug for FencedTransitionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionRequest(<redacted>)")
    }
}

/// A V2 request whose identity commits to its exact canonical body.
///
/// Construct it once with [`FencedTransitionV2Request::new`] and retain the
/// complete value (or its serde representation) for every retry and status
/// request. [`FencedTransitionV2Request::validate`] recomputes the body
/// commitment. Therefore substituting a lease or mutation under an existing
/// V2 ID deterministically returns
/// `StoreError::FencedTransitionRequestConflict`, even if the original
/// receipt rows have already been reclaimed.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FencedTransitionV2Request {
    request_id: FencedTransitionV2RequestId,
    lease: FencedTransitionLease,
    mutation: FencedTransitionMutation,
}

impl FencedTransitionV2Request {
    /// Construct a new self-authenticating V2 request.
    ///
    /// Reusing the same `epoch` and `nonce` with the same lease and mutation
    /// produces the same ID, which supports stable caller retries. Reusing
    /// them with another valid body produces a different full ID.
    pub fn new(
        epoch: FencedTransitionV2HistoryEpoch,
        nonce: FencedTransitionV2CallerNonce,
        lease: FencedTransitionLease,
        mutation: FencedTransitionMutation,
    ) -> Result<Self, StoreError> {
        let commitment = v2_body_commitment(epoch, nonce, &lease, &mutation)?;
        let request = Self {
            request_id: FencedTransitionV2RequestId::from_parts(epoch, nonce, commitment),
            lease,
            mutation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Reconstruct a V2 request from an externally retained full ID and body.
    ///
    /// This is primarily for serde-adjacent integrations. It never accepts a
    /// substituted body: validation recomputes the commitment and reports
    /// `FencedTransitionRequestConflict` on a mismatch.
    pub fn from_parts(
        request_id: FencedTransitionV2RequestId,
        lease: FencedTransitionLease,
        mutation: FencedTransitionMutation,
    ) -> Result<Self, StoreError> {
        let request = Self {
            request_id,
            lease,
            mutation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Complete self-authenticating request identity; never truncate it for
    /// storage or comparison.
    pub const fn request_id(&self) -> FencedTransitionV2RequestId {
        self.request_id
    }

    /// Lease action committed by this request.
    pub const fn lease(&self) -> &FencedTransitionLease {
        &self.lease
    }

    /// Same-record mutation committed by this request.
    pub const fn mutation(&self) -> &FencedTransitionMutation {
        &self.mutation
    }

    /// Recompute the full SHA-256 commitment from this body's canonical form.
    pub fn recomputed_body_commitment(
        &self,
    ) -> Result<[u8; FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES], StoreError> {
        v2_body_commitment(
            self.request_id.epoch,
            self.request_id.nonce,
            &self.lease,
            &self.mutation,
        )
    }

    /// Whether `other` is the same valid full V2 identity and canonical body.
    ///
    /// This is suitable for fail-closed response and status correlation; it
    /// compares the complete 56-byte ID rather than any V1-sized prefix.
    pub fn matches(&self, other: &Self) -> bool {
        self.request_id == other.request_id
            && self.lease == other.lease
            && self.mutation == other.mutation
            && self.validate().is_ok()
            && other.validate().is_ok()
    }

    /// Validate time-independent V2 structure and its self-authentication.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.request_id.epoch.get() == 0 {
            return Err(StoreError::InvalidKey(
                INVALID_TRANSITION_V2_HISTORY_EPOCH.into(),
            ));
        }
        if self.recomputed_body_commitment()? != self.request_id.body_commitment {
            return Err(StoreError::FencedTransitionRequestConflict);
        }
        validate_fenced_transition_v2_request_timestamps(&self.lease, &self.mutation)?;
        self.lease.validate()?;
        self.mutation.validate_for_lease(&self.lease)?;
        Ok(())
    }

    /// Validate time-dependent V2 request constraints at committed logical
    /// time after verifying its self-authenticating identity.
    pub fn validate_at(&self, logical_time: Timestamp) -> Result<(), StoreError> {
        // A substituted body must always classify as a commitment conflict
        // before a caller-controlled logical time or derived deadline can
        // select a semantic error.
        self.validate()?;
        if !fenced_transition_v2_timestamp_is_in_range(logical_time) {
            return Err(StoreError::InvalidKey(
                "fenced_transition_v2_timestamp_invalid".into(),
            ));
        }
        validate_fenced_transition_v2_derived_deadline(logical_time, self.lease.ttl())?;
        if let FencedTransitionMutation::RefreshTtl { ttl, .. } = &self.mutation {
            validate_fenced_transition_v2_derived_deadline(logical_time, *ttl)?;
        }
        self.lease.validate_at(logical_time)?;
        self.mutation.validate_at(logical_time)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FencedTransitionV2RequestWire {
    request_id: FencedTransitionV2RequestId,
    lease: FencedTransitionLease,
    mutation: FencedTransitionMutation,
}

impl<'de> Deserialize<'de> for FencedTransitionV2Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = FencedTransitionV2RequestWire::deserialize(deserializer)?;
        // This is deliberately wire-structural only. A peer can preserve a
        // valid full ID while changing an otherwise representable body. That
        // retry must materialize so ingress can call `validate()` and return
        // RequestConflict *before* reporting the changed body's semantic
        // error or looking up reclaimable history. The wire DTO and nested
        // Deserialize implementations still reject malformed enum, field,
        // model, epoch, timestamp, and payload representations. Safe `new`
        // and `from_parts` remain the constructors that require a matching
        // self-commitment.
        Ok(Self {
            request_id: wire.request_id,
            lease: wire.lease,
            mutation: wire.mutation,
        })
    }
}

/// Return whether a timestamp lies in V2's feature-independent wire range.
///
/// Follower command admission and receipt decoding use this helper in addition
/// to parsing a `Timestamp`, because the parser's date range may vary with
/// optional dependency features.
pub(crate) fn fenced_transition_v2_timestamp_is_in_range(timestamp: Timestamp) -> bool {
    (FENCED_TRANSITION_V2_MIN_TIMESTAMP_UNIX_SECONDS
        ..=FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS)
        .contains(&timestamp.as_offset_datetime().unix_timestamp())
}

fn validate_fenced_transition_v2_request_timestamps(
    lease: &FencedTransitionLease,
    mutation: &FencedTransitionMutation,
) -> Result<(), StoreError> {
    let timestamps = match lease {
        FencedTransitionLease::Acquire { .. } => None,
        FencedTransitionLease::Renew { lease, .. } => {
            Some([lease.acquired_at(), lease.expires_at()])
        }
    };
    if timestamps.is_some_and(|values| {
        values
            .into_iter()
            .any(|timestamp| !fenced_transition_v2_timestamp_is_in_range(timestamp))
    }) || mutation.record().is_some_and(|record| {
        record
            .expires_at
            .is_some_and(|timestamp| !fenced_transition_v2_timestamp_is_in_range(timestamp))
    }) {
        return Err(StoreError::InvalidKey(
            "fenced_transition_v2_timestamp_invalid".into(),
        ));
    }
    Ok(())
}

fn validate_fenced_transition_v2_derived_deadline(
    logical_time: Timestamp,
    ttl: Duration,
) -> Result<(), StoreError> {
    let deadline = checked_session_deadline(logical_time, ttl)?;
    if !fenced_transition_v2_timestamp_is_in_range(deadline) {
        // `checked_session_deadline` already uses InvalidSessionTtl when a
        // normal `time` build cannot represent this deadline. Preserve that
        // exact admitted deterministic error when a large-date build can
        // calculate the same out-of-profile timestamp.
        return Err(StoreError::InvalidSessionTtl);
    }
    Ok(())
}

impl fmt::Debug for FencedTransitionV2Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionV2Request(<redacted>)")
    }
}

/// Return the immutable digest of V2's fixed protocol profile.
///
/// It covers the frozen body encoder, complete outer-ID derivation, validation
/// bounds, receipt codec, command codecs, status meanings, initial history
/// epoch, capacity, operational target, and reclaim batch. V2 intentionally
/// has no negotiable history-limit fields: two implementations advertising
/// [`AtomicFencedTransitionCapability::V2`] must report the same digest.
pub fn fenced_transition_v2_profile_digest() -> [u8; FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES] {
    fenced_transition_v2_profile_digest_with_retention_inputs(
        FENCED_TRANSITION_V2_RETENTION_PROFILE_INPUTS,
    )
}

#[cfg(test)]
fn fenced_transition_v2_profile_digest_with_outcome_retention(
    outcome_retention: Duration,
) -> [u8; FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES] {
    fenced_transition_v2_profile_digest_with_retention_inputs([
        outcome_retention.as_secs(),
        outcome_retention.subsec_nanos() as u64,
    ])
}

fn fenced_transition_v2_profile_digest_with_retention_inputs(
    retention_inputs: [u64; 2],
) -> [u8; FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES] {
    let mut hasher = Sha256::new();
    hasher.update(b"openpacketcore/fenced-transition/v2/profile\0");
    hasher.update(FENCED_TRANSITION_SCHEMA_V2.to_be_bytes());
    hasher.update(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.as_bytes());
    hasher.update([0]);
    hasher.update(FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_MAGIC);
    hasher.update([FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_REVISION]);
    hasher.update((FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES as u64).to_be_bytes());
    hasher.update(FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_SCHEMA_DESCRIPTOR.as_bytes());
    hasher.update([0]);
    hasher.update(FENCED_TRANSITION_V2_VALIDATION_SCHEMA_REVISION.to_be_bytes());
    hasher.update(FENCED_TRANSITION_V2_VALIDATION_SCHEMA_DESCRIPTOR.as_bytes());
    hasher.update([0]);
    for input in FENCED_TRANSITION_V2_VALIDATION_PROFILE_INPUTS {
        hasher.update(input.to_be_bytes());
    }
    hasher.update([0]);
    hasher.update(FENCED_TRANSITION_V2_COMMAND_TRANSPORT_SCHEMA_REVISION.to_be_bytes());
    hasher.update(FENCED_TRANSITION_V2_COMMAND_TRANSPORT_SCHEMA_DESCRIPTOR.as_bytes());
    hasher.update([0]);
    for input in FENCED_TRANSITION_V2_COMMAND_TRANSPORT_PROFILE_INPUTS {
        hasher.update(input.to_be_bytes());
    }
    hasher.update([0]);
    hasher.update(FENCED_TRANSITION_V2_RECORD_ENVELOPE_SCHEMA_REVISION.to_be_bytes());
    hasher.update(FENCED_TRANSITION_V2_RECORD_ENVELOPE_SCHEMA_DESCRIPTOR.as_bytes());
    hasher.update([0]);
    hasher.update(
        crate::consensus::types::SESSION_CONSENSUS_V2_APPLIED_DIGEST_ENCODING_VERSION.to_be_bytes(),
    );
    hasher.update(
        crate::consensus::types::SESSION_CONSENSUS_V2_APPLIED_DIGEST_SCHEMA_DESCRIPTOR.as_bytes(),
    );
    hasher.update([0]);
    hasher.update(
        crate::consensus::types::SESSION_CONSENSUS_V2_COMMAND_WIRE_SCHEMA_DESCRIPTOR.as_bytes(),
    );
    hasher.update([0]);
    hasher.update(FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_REVISION.to_be_bytes());
    hasher.update(FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_DESCRIPTOR.as_bytes());
    hasher.update([0]);
    hasher.update(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH.to_be_bytes());
    hasher.update(FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH.to_be_bytes());
    hasher.update((FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64).to_be_bytes());
    hasher.update((FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET as u64).to_be_bytes());
    hasher.update((FENCED_TRANSITION_V2_RECLAIM_BATCH as u64).to_be_bytes());
    for input in retention_inputs {
        hasher.update(input.to_be_bytes());
    }
    hasher.update((FENCED_TRANSITION_MAX_OUTCOME_BYTES as u64).to_be_bytes());
    hasher.update(
        b"lifecycle=validate-self-auth-before-floor;active-only;retire-floor-before-delete;no-active-during-reclaim;final-open-next\0",
    );
    hasher.update(b"reclaim=ordered(epoch,ordinal);status-error-revision=");
    hasher.update(FENCED_TRANSITION_V2_ERROR_STATUS_REVISION.to_be_bytes());
    hasher.update(
        b";receipt-errors=request-conflict,request-expired,history-full,history-epoch-retired,history-epoch-not-active,retention-exhausted,storage-exhausted,topology-authority-revoked,lease-or-mutation-rejection;statuses=recorded,request-conflict,expired,retired,history-full,not-found,epoch-not-active,retention-exhausted\0",
    );
    hasher.finalize().into()
}

fn v2_body_commitment(
    epoch: FencedTransitionV2HistoryEpoch,
    nonce: FencedTransitionV2CallerNonce,
    lease: &FencedTransitionLease,
    mutation: &FencedTransitionMutation,
) -> Result<[u8; FENCED_TRANSITION_V2_BODY_COMMITMENT_BYTES], StoreError> {
    let body = v2_canonical_body(lease, mutation);
    let mut hasher = Sha256::new();
    hasher.update(FENCED_TRANSITION_V2_COMMITMENT_DOMAIN);
    hasher.update(FENCED_TRANSITION_SCHEMA_V2.to_be_bytes());
    hasher.update(epoch.get().to_be_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update((body.len() as u64).to_be_bytes());
    hasher.update(body);
    Ok(hasher.finalize().into())
}

/// Encode V2's frozen canonical request body without relying on Serde.
///
/// Every nested value is encoded explicitly, with tags selected here rather
/// than from Rust declaration order or serde enum names. This is intentionally
/// private: callers use the self-authenticating V2 request ID, while the
/// profile descriptor fixes the interoperable bytes.
fn v2_canonical_body(
    lease: &FencedTransitionLease,
    mutation: &FencedTransitionMutation,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(1); // Canonical-body encoding revision.
    append_v2_lease(&mut body, lease);
    append_v2_mutation(&mut body, mutation);
    body
}

fn append_v2_lease(out: &mut Vec<u8>, lease: &FencedTransitionLease) {
    match lease {
        FencedTransitionLease::Acquire {
            key,
            owner,
            expected_fence,
            ttl,
        } => {
            out.push(1);
            append_v2_session_key(out, key);
            append_v2_bytes(out, owner.as_str().as_bytes());
            out.extend_from_slice(&expected_fence.get().to_be_bytes());
            append_v2_duration(out, *ttl);
        }
        FencedTransitionLease::Renew { lease, ttl } => {
            out.push(2);
            append_v2_lease_guard(out, lease);
            append_v2_duration(out, *ttl);
        }
    }
}

fn append_v2_mutation(out: &mut Vec<u8>, mutation: &FencedTransitionMutation) {
    match mutation {
        FencedTransitionMutation::Create { record } => {
            out.push(17);
            append_v2_record(out, record);
        }
        FencedTransitionMutation::Update {
            expected_generation,
            record,
        } => {
            out.push(18);
            out.extend_from_slice(&expected_generation.get().to_be_bytes());
            append_v2_record(out, record);
        }
        FencedTransitionMutation::Delete {
            expected_generation,
        } => {
            out.push(19);
            out.extend_from_slice(&expected_generation.get().to_be_bytes());
        }
        FencedTransitionMutation::RefreshTtl {
            expected_generation,
            ttl,
        } => {
            out.push(20);
            out.extend_from_slice(&expected_generation.get().to_be_bytes());
            append_v2_duration(out, *ttl);
        }
    }
}

fn append_v2_session_key(out: &mut Vec<u8>, key: &SessionKey) {
    out.push(33);
    append_v2_bytes(out, key.tenant.as_str().as_bytes());
    append_v2_bytes(out, key.nf_kind.as_str().as_bytes());
    match &key.key_type {
        crate::model::SessionKeyType::SubscriberContext => out.push(1),
        crate::model::SessionKeyType::PduSession => out.push(2),
        crate::model::SessionKeyType::TeidMapping => out.push(3),
        crate::model::SessionKeyType::PfcpSeid => out.push(4),
        crate::model::SessionKeyType::HandoverTransaction => out.push(5),
        crate::model::SessionKeyType::Other(custom) => {
            out.push(6);
            append_v2_bytes(out, custom.as_str().as_bytes());
        }
    }
    append_v2_bytes(out, key.stable_id.as_ref());
}

fn append_v2_lease_guard(out: &mut Vec<u8>, lease: &LeaseGuard) {
    out.push(34);
    append_v2_session_key(out, lease.key());
    append_v2_bytes(out, lease.owner().as_str().as_bytes());
    out.extend_from_slice(&lease.fence().get().to_be_bytes());
    append_v2_timestamp(out, lease.acquired_at());
    append_v2_timestamp(out, lease.expires_at());
    out.extend_from_slice(&lease.credential_id().to_be_bytes());
}

fn append_v2_record(out: &mut Vec<u8>, record: &StoredSessionRecord) {
    out.push(35);
    append_v2_session_key(out, &record.key);
    out.extend_from_slice(&record.generation.get().to_be_bytes());
    append_v2_bytes(out, record.owner.as_str().as_bytes());
    out.extend_from_slice(&record.fence.get().to_be_bytes());
    out.push(match record.state_class {
        crate::model::StateClass::AuthoritativeSession => 1,
        crate::model::StateClass::DataplaneLookup => 2,
        crate::model::StateClass::ReplicatedDr => 3,
        crate::model::StateClass::TelemetryDerived => 4,
        crate::model::StateClass::EphemeralProcedure => 5,
    });
    append_v2_bytes(out, record.state_type.as_str().as_bytes());
    match record.expires_at {
        None => out.push(0),
        Some(expires_at) => {
            out.push(1);
            append_v2_timestamp(out, expires_at);
        }
    }
    out.push(match record.payload.encoding() {
        crate::record::SessionPayloadEncoding::Plaintext => 1,
        crate::record::SessionPayloadEncoding::LegacyPlaintext => 2,
        crate::record::SessionPayloadEncoding::EnvelopeV1 => 3,
        crate::record::SessionPayloadEncoding::Unclassified => 4,
    });
    append_v2_bytes(out, record.payload.as_bytes());
}

fn append_v2_duration(out: &mut Vec<u8>, duration: Duration) {
    out.extend_from_slice(&duration.as_secs().to_be_bytes());
    out.extend_from_slice(&duration.subsec_nanos().to_be_bytes());
}

fn append_v2_timestamp(out: &mut Vec<u8>, timestamp: Timestamp) {
    let timestamp = timestamp.as_offset_datetime();
    out.extend_from_slice(&timestamp.unix_timestamp().to_be_bytes());
    out.extend_from_slice(&timestamp.nanosecond().to_be_bytes());
}

fn append_v2_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Typed record effect of one committed transition.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencedTransitionMutationResult {
    /// An absent record was created.
    Created,
    /// An existing record was replaced.
    Updated,
    /// The exact existing record was deleted.
    Deleted,
    /// The exact existing record's TTL was replaced.
    TtlRefreshed {
        /// Committed absolute deadline.
        expires_at: Timestamp,
    },
}

impl fmt::Debug for FencedTransitionMutationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionMutationResult(<redacted>)")
    }
}

/// Exact result recorded at the transition's single consensus position.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedTransitionOutcome {
    lease: LeaseGuard,
    committed_generation: Generation,
    mutation: FencedTransitionMutationResult,
    recorded_at: Timestamp,
    retained_until: Timestamp,
}

impl FencedTransitionOutcome {
    pub(crate) fn new(
        lease: LeaseGuard,
        committed_generation: Generation,
        mutation: FencedTransitionMutationResult,
        recorded_at: Timestamp,
    ) -> Result<Self, StoreError> {
        let retained_until =
            checked_session_deadline(recorded_at, FENCED_TRANSITION_OUTCOME_RETENTION)?;
        let outcome = Self {
            lease,
            committed_generation,
            mutation,
            recorded_at,
            retained_until,
        };
        outcome.validate()?;
        Ok(outcome)
    }

    /// Lease credential acquired or renewed by the same committed entry.
    pub const fn lease(&self) -> &LeaseGuard {
        &self.lease
    }

    /// Generation created, updated, deleted, or TTL-refreshed by the entry.
    pub const fn committed_generation(&self) -> Generation {
        self.committed_generation
    }

    /// Typed same-record effect.
    pub const fn mutation(&self) -> FencedTransitionMutationResult {
        self.mutation
    }

    /// Committed logical timestamp used for lease and record expiry admission.
    pub const fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }

    /// End of the exact-result recovery window.
    pub const fn retained_until(&self) -> Timestamp {
        self.retained_until
    }

    /// Whether exact replay/status has expired at a committed logical time.
    pub fn is_expired_at(&self, logical_time: Timestamp) -> bool {
        self.retained_until <= logical_time
    }

    /// Validate a deserialized outcome against its complete transition body.
    ///
    /// The outcome's own committed timestamp is authoritative; callers do not
    /// supply a wall-clock value that could accidentally validate a receipt at
    /// a different logical time.
    pub fn matches_request(&self, request: &FencedTransitionRequest) -> bool {
        self.matches_request_at(request, self.recorded_at)
    }

    /// Validate that one serialized success is the exact result shape implied
    /// by its bound request at the committed admission time.
    pub(crate) fn matches_request_at(
        &self,
        request: &FencedTransitionRequest,
        logical_time: Timestamp,
    ) -> bool {
        if request.validate_at(logical_time).is_err() {
            return false;
        }
        self.matches_transition_body_at(request.lease(), request.mutation(), logical_time)
    }

    /// Validate that this outcome is the exact result shape implied by a V2
    /// request at its committed admission time.
    ///
    /// This checks the V2 request's complete self-authenticating ID before it
    /// checks the shared lease/mutation result shape. It deliberately does not
    /// turn a V2 identity into V1's 16-byte request namespace.
    pub fn matches_v2_request(&self, request: &FencedTransitionV2Request) -> bool {
        if request.validate_at(self.recorded_at).is_err() {
            return false;
        }
        self.matches_transition_body_at(request.lease(), request.mutation(), self.recorded_at)
    }

    fn matches_transition_body_at(
        &self,
        lease: &FencedTransitionLease,
        mutation: &FencedTransitionMutation,
        logical_time: Timestamp,
    ) -> bool {
        if self.validate().is_err()
            || self.recorded_at != logical_time
            || self.lease.key() != lease.key()
            || self.lease.owner() != lease.owner()
            || !lease
                .committed_fence()
                .is_ok_and(|fence| self.lease.fence() == fence)
            || !checked_session_deadline(logical_time, lease.ttl())
                .is_ok_and(|expires_at| self.lease.expires_at() == expires_at)
        {
            return false;
        }
        match lease {
            FencedTransitionLease::Acquire { .. } => {
                if self.lease.acquired_at() != logical_time || self.lease.credential_id() == 0 {
                    return false;
                }
            }
            FencedTransitionLease::Renew { lease, .. } => {
                if self.lease.acquired_at() != lease.acquired_at()
                    || self.lease.credential_id() != lease.credential_id()
                {
                    return false;
                }
            }
        }
        match (mutation, self.mutation) {
            (
                FencedTransitionMutation::Create { record },
                FencedTransitionMutationResult::Created,
            ) => self.committed_generation == record.generation,
            (
                FencedTransitionMutation::Update { record, .. },
                FencedTransitionMutationResult::Updated,
            ) => self.committed_generation == record.generation,
            (
                FencedTransitionMutation::Delete {
                    expected_generation,
                },
                FencedTransitionMutationResult::Deleted,
            ) => self.committed_generation == *expected_generation,
            (
                FencedTransitionMutation::RefreshTtl {
                    expected_generation,
                    ttl,
                },
                FencedTransitionMutationResult::TtlRefreshed { expires_at },
            ) => {
                self.committed_generation == *expected_generation
                    && checked_session_deadline(logical_time, *ttl)
                        .is_ok_and(|expected| expires_at == expected)
            }
            _ => false,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        let maximum_lease_expiry =
            checked_session_deadline(self.recorded_at, crate::MAX_SESSION_TTL).ok();
        if self.lease.fence().get() == 0
            || self.lease.credential_id() == 0
            || self.lease.acquired_at() > self.recorded_at
            || self.lease.expires_at() <= self.recorded_at
            || maximum_lease_expiry.is_some_and(|maximum| self.lease.expires_at() > maximum)
            || self.retained_until <= self.recorded_at
        {
            return Err(StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()));
        }
        if let FencedTransitionMutationResult::TtlRefreshed { expires_at } = self.mutation {
            if expires_at <= self.recorded_at
                || maximum_lease_expiry.is_some_and(|maximum| expires_at > maximum)
            {
                return Err(StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()));
            }
        }
        let maximum_retained_until =
            checked_session_deadline(self.recorded_at, FENCED_TRANSITION_OUTCOME_RETENTION)
                .map_err(|_| StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()))?;
        if self.retained_until != maximum_retained_until {
            return Err(StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()));
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|_| StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()))?;
        if encoded.len() > FENCED_TRANSITION_MAX_OUTCOME_BYTES {
            return Err(StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()));
        }
        Ok(())
    }
}

impl fmt::Debug for FencedTransitionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionOutcome(<redacted>)")
    }
}

/// One fresh, exact-key observation used to prepare a deterministic acquire.
///
/// The record and durable per-key fence floor are read in the same backend
/// transaction after a consensus read barrier. A deleted key therefore still
/// exposes its fence floor without granting fence-allocation authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedTransitionObservation {
    record: Option<StoredSessionRecord>,
    current_fence: FenceToken,
}

impl FencedTransitionObservation {
    pub(crate) fn new(
        record: Option<StoredSessionRecord>,
        current_fence: FenceToken,
    ) -> Result<Self, StoreError> {
        if record
            .as_ref()
            .is_some_and(|record| record.fence > current_fence)
        {
            return Err(StoreError::Serialization(
                "fenced_transition_observation_invalid".into(),
            ));
        }
        Ok(Self {
            record,
            current_fence,
        })
    }

    /// Live record at the committed observation time, if present.
    pub const fn record(&self) -> Option<&StoredSessionRecord> {
        self.record.as_ref()
    }

    /// Durable fence floor for the exact key, including deleted history.
    pub const fn current_fence(&self) -> FenceToken {
        self.current_fence
    }
}

impl fmt::Debug for FencedTransitionObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionObservation(<redacted>)")
    }
}

/// Exact, linearized status of one retained transition request/body pair.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencedTransitionStatus {
    /// The exact success or deterministic no-effect error remains in its
    /// recovery window.
    ///
    /// The result is heap allocated so this public status enum remains small
    /// even though a successful outcome carries a complete lease credential.
    /// `Box` is serialization-transparent, preserving the persisted wire
    /// representation of this variant.
    Recorded(Box<Result<FencedTransitionOutcome, StoreError>>),
    /// The identity is durably bound to a different canonical request body.
    RequestConflict,
    /// The identity/body binding exists but its exact-result window elapsed.
    Expired,
    /// The identity is unbound, but the permanent receipt ledger cannot bind
    /// another ID for this consensus identity.
    ///
    /// An ID rejected this way remains unbound, so both its same-body and
    /// different-body retries return `HistoryFull` rather than
    /// `RequestConflict`.
    HistoryFull,
    /// The identity is unbound, but committed logical time can no longer
    /// represent the protocol's complete exact-result retention window.
    ///
    /// This horizon is absorbing because committed logical time never moves
    /// backward. Same-body and different-body attempts therefore remain
    /// deterministic no-effect rejections under this still-unbound ID.
    RetentionExhausted,
    /// No committed request/body binding existed at the status log position.
    NotFound,
}

impl fmt::Debug for FencedTransitionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionStatus(<redacted>)")
    }
}

/// Durable, non-secret summary of V2 receipt-history lifecycle.
///
/// `active_epoch` is the only epoch that admits new V2 requests. Epochs at or
/// below `retired_through` are permanently closed. `reclaim_epoch` and
/// `reclaim_remaining` expose durable, CAS-safe progress through the ordered
/// `(epoch, ordinal)` reclamation of closed receipt rows. After activation
/// exactly one of `active_epoch` or `reclaim_epoch` is present. An
/// implementation clears `active_epoch` before beginning reclamation and
/// opens the immediate successor epoch only after the final reclaim batch
/// commits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FencedTransitionV2HistoryState {
    active_epoch: Option<FencedTransitionV2HistoryEpoch>,
    retired_through: Option<FencedTransitionV2HistoryEpoch>,
    reclaim_epoch: Option<FencedTransitionV2HistoryEpoch>,
    reclaim_remaining: usize,
    generation: u64,
    bound_entries: usize,
    reclaimed_entries: u64,
}

/// Frozen serde shape for [`FencedTransitionV2HistoryState`].
///
/// Counts are serialized as `u64`, never `usize`, so this persisted public
/// contract is independent of the architecture of the encoder or decoder.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FencedTransitionV2HistoryStateWire {
    active_epoch: Option<FencedTransitionV2HistoryEpoch>,
    retired_through: Option<FencedTransitionV2HistoryEpoch>,
    reclaim_epoch: Option<FencedTransitionV2HistoryEpoch>,
    reclaim_remaining: u64,
    generation: u64,
    bound_entries: u64,
    reclaimed_entries: u64,
}

impl Serialize for FencedTransitionV2HistoryState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        FencedTransitionV2HistoryStateWire {
            active_epoch: self.active_epoch,
            retired_through: self.retired_through,
            reclaim_epoch: self.reclaim_epoch,
            reclaim_remaining: self.reclaim_remaining as u64,
            generation: self.generation,
            bound_entries: self.bound_entries as u64,
            reclaimed_entries: self.reclaimed_entries,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FencedTransitionV2HistoryState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = FencedTransitionV2HistoryStateWire::deserialize(deserializer)?;
        let reclaim_remaining = usize::try_from(wire.reclaim_remaining).map_err(|_| {
            serde::de::Error::custom("fenced transition V2 reclaim count is invalid")
        })?;
        let bound_entries = usize::try_from(wire.bound_entries)
            .map_err(|_| serde::de::Error::custom("fenced transition V2 bound count is invalid"))?;
        Self::new(
            wire.active_epoch,
            wire.retired_through,
            wire.reclaim_epoch,
            reclaim_remaining,
            wire.generation,
            bound_entries,
            wire.reclaimed_entries,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl FencedTransitionV2HistoryState {
    /// Construct one validated durable history-state summary.
    pub fn new(
        active_epoch: Option<FencedTransitionV2HistoryEpoch>,
        retired_through: Option<FencedTransitionV2HistoryEpoch>,
        reclaim_epoch: Option<FencedTransitionV2HistoryEpoch>,
        reclaim_remaining: usize,
        generation: u64,
        bound_entries: usize,
        reclaimed_entries: u64,
    ) -> Result<Self, StoreError> {
        let active_state_is_valid = match (active_epoch, retired_through, reclaim_epoch) {
            (Some(active), None, None) => {
                active.get() == FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH && reclaim_remaining == 0
            }
            (Some(active), Some(retired), None) => {
                retired
                    .get()
                    .checked_add(1)
                    .is_some_and(|expected| active.get() == expected)
                    && reclaim_remaining == 0
            }
            _ => false,
        };
        let reclaim_state_is_valid = matches!(
            (active_epoch, retired_through, reclaim_epoch),
            (None, Some(retired), Some(reclaim)) if reclaim == retired
        ) && bound_entries == 0
            && (1..=FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES).contains(&reclaim_remaining);

        if !(active_state_is_valid || reclaim_state_is_valid)
            || bound_entries > FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            || generation > FENCED_TRANSITION_V2_MAX_DURABLE_GENERATION
        {
            return Err(StoreError::Serialization(
                "fenced_transition_v2_history_state_invalid".into(),
            ));
        }
        Ok(Self {
            active_epoch,
            retired_through,
            reclaim_epoch,
            reclaim_remaining,
            generation,
            bound_entries,
            reclaimed_entries,
        })
    }

    /// Epoch currently accepting new V2 request identities, if initialized.
    pub const fn active_epoch(&self) -> Option<FencedTransitionV2HistoryEpoch> {
        self.active_epoch
    }

    /// Greatest epoch permanently retired and closed to new requests.
    pub const fn retired_through(&self) -> Option<FencedTransitionV2HistoryEpoch> {
        self.retired_through
    }

    /// Retired epoch currently being reclaimed in ordered bounded batches.
    pub const fn reclaim_epoch(&self) -> Option<FencedTransitionV2HistoryEpoch> {
        self.reclaim_epoch
    }

    /// Receipt rows remaining in `reclaim_epoch` before the next epoch opens.
    pub const fn reclaim_remaining(&self) -> usize {
        self.reclaim_remaining
    }

    /// Monotonic durable state generation used to observe lifecycle changes.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Number of currently bound receipts in the active history epoch.
    pub const fn bound_entries(&self) -> usize {
        self.bound_entries
    }

    /// Cumulative number of obsolete receipt rows reclaimed durably.
    pub const fn reclaimed_entries(&self) -> u64 {
        self.reclaimed_entries
    }
}

impl fmt::Debug for FencedTransitionV2HistoryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionV2HistoryState(<redacted>)")
    }
}

/// Exact status of one V2 request under its complete self-authenticating ID.
///
/// `RequestConflict` includes a supplied body whose recomputed commitment
/// differs from the retained full ID. `Retired` is terminal for its epoch and
/// remains so after physical receipt rows have been reclaimed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum FencedTransitionV2Status {
    /// The exact success or deterministic no-effect error remains recorded.
    Recorded(Box<Result<FencedTransitionOutcome, StoreError>>),
    /// The complete ID is bound to a different canonical body.
    RequestConflict,
    /// The exact-result recovery window elapsed while its binding remains
    /// closed to replay.
    Expired,
    /// The request epoch is retired or otherwise closed permanently.
    Retired,
    /// The active epoch cannot durably bind another request before rotation.
    HistoryFull,
    /// No binding exists for this complete V2 ID in the active epoch.
    NotFound,
    /// The request names an epoch above the irreversible retired floor that is
    /// not currently active, including the successor while its predecessor is
    /// being reclaimed. This is a deterministic no-effect state, but unlike
    /// `Retired` it is not terminal for that epoch.
    EpochNotActive,
    /// The committed logical clock cannot retain a newly bound result for the
    /// mandatory recovery window. The request was not applied or bound.
    RetentionExhausted,
}

impl fmt::Debug for FencedTransitionV2Status {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionV2Status(<redacted>)")
    }
}

fn validate_positive_ttl(ttl: Duration) -> Result<(), StoreError> {
    if ttl.is_zero() {
        return Err(StoreError::InvalidSessionTtl);
    }
    validate_session_ttl(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptedSessionPayload, SessionKeyType, StableId, StateClass, StateType};
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("fenced-transition-model"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"opaque-id")).expect("stable ID"),
        }
    }

    fn timestamp(seconds: i64) -> Timestamp {
        Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(seconds),
        )
    }

    fn lease_guard(key: SessionKey, owner: OwnerId, fence: FenceToken) -> LeaseGuard {
        LeaseGuard::new(key, owner, fence, timestamp(10), timestamp(70), 1)
    }

    fn record(
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        generation: u64,
    ) -> StoredSessionRecord {
        StoredSessionRecord {
            key,
            generation: Generation::new(generation),
            owner,
            fence,
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("opaque-state").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"opaque"),
        }
    }

    #[test]
    fn acquire_create_requires_exact_successor_fence_and_generation() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let lease = FencedTransitionLease::acquire(
            key(),
            owner.clone(),
            FenceToken::new(7),
            Duration::from_secs(30),
        )
        .expect("lease action");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([1; 16]),
            lease.clone(),
            FencedTransitionMutation::create(record(key(), owner.clone(), FenceToken::new(8), 1)),
        );
        assert!(request.is_ok());

        let wrong_fence = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([2; 16]),
            lease.clone(),
            FencedTransitionMutation::create(record(key(), owner.clone(), FenceToken::new(9), 1)),
        );
        assert!(matches!(wrong_fence, Err(StoreError::InvalidKey(_))));

        let mut another_key = key();
        another_key.tenant = TenantId::from_static("different-fenced-transition-model");
        let wrong_key = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([3; 16]),
            lease.clone(),
            FencedTransitionMutation::create(record(
                another_key,
                owner.clone(),
                FenceToken::new(8),
                1,
            )),
        );
        assert!(matches!(wrong_key, Err(StoreError::InvalidKey(_))));

        let wrong_owner = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([4; 16]),
            lease.clone(),
            FencedTransitionMutation::create(record(
                key(),
                OwnerId::new("owner-b").expect("owner"),
                FenceToken::new(8),
                1,
            )),
        );
        assert!(matches!(wrong_owner, Err(StoreError::InvalidKey(_))));

        let wrong_generation = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([5; 16]),
            lease,
            FencedTransitionMutation::create(record(key(), owner, FenceToken::new(8), 2)),
        );
        assert!(matches!(wrong_generation, Err(StoreError::InvalidKey(_))));
    }

    #[test]
    fn transition_ttls_must_be_positive() {
        let owner = OwnerId::new("owner-a").expect("owner");
        assert!(matches!(
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::ZERO,
            ),
            Err(StoreError::InvalidSessionTtl)
        ));
        assert!(matches!(
            FencedTransitionLease::renew(
                lease_guard(key(), owner, FenceToken::new(8)),
                Duration::ZERO,
            ),
            Err(StoreError::InvalidSessionTtl)
        ));
        assert!(matches!(
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::ZERO),
            Err(StoreError::InvalidSessionTtl)
        ));
    }

    #[test]
    fn transition_ttls_accept_the_exact_maximum_and_reject_one_nanosecond_more() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let maximum = crate::MAX_SESSION_TTL;
        let one_over = maximum + Duration::from_nanos(1);

        assert!(
            FencedTransitionLease::acquire(key(), owner.clone(), FenceToken::new(7), maximum,)
                .is_ok()
        );
        assert!(matches!(
            FencedTransitionLease::acquire(key(), owner.clone(), FenceToken::new(7), one_over),
            Err(StoreError::InvalidSessionTtl)
        ));

        assert!(FencedTransitionLease::renew(
            lease_guard(key(), owner.clone(), FenceToken::new(8)),
            maximum,
        )
        .is_ok());
        assert!(matches!(
            FencedTransitionLease::renew(
                lease_guard(key(), owner.clone(), FenceToken::new(8)),
                one_over,
            ),
            Err(StoreError::InvalidSessionTtl)
        ));

        assert!(FencedTransitionMutation::refresh_ttl(Generation::new(1), maximum).is_ok());
        assert!(matches!(
            FencedTransitionMutation::refresh_ttl(Generation::new(1), one_over),
            Err(StoreError::InvalidSessionTtl)
        ));
    }

    #[test]
    fn v2_validation_profile_bounds_match_request_construction() {
        let maximum = crate::MAX_SESSION_TTL;
        let v2_key = SessionKey {
            tenant: TenantId::new("t".repeat(128)).expect("maximum tenant slug"),
            nf_kind: NetworkFunctionKind::new("n".repeat(64)).expect("maximum NF kind slug"),
            key_type: SessionKeyType::other("k".repeat(crate::SESSION_KEY_TYPE_MAX_BYTES))
                .expect("maximum custom key type"),
            stable_id: StableId::new(Bytes::from(vec![0xA5; crate::STABLE_ID_MAX_BYTES]))
                .expect("maximum stable ID"),
        };
        let owner = OwnerId::new("o".repeat(crate::OWNER_ID_MAX_BYTES)).expect("maximum owner");
        let record = StoredSessionRecord {
            key: v2_key.clone(),
            generation: Generation::new(1),
            owner: owner.clone(),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("s".repeat(crate::STATE_TYPE_MAX_BYTES))
                .expect("maximum state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"profile-boundary"),
        };
        let request = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                .expect("initial epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x5A; 16]),
            FencedTransitionLease::acquire(v2_key, owner, FenceToken::new(0), maximum)
                .expect("exact maximum V2 TTL"),
            FencedTransitionMutation::create(record),
        )
        .expect("maximum modeled V2 request");
        assert!(request.validate().is_ok());

        assert!(TenantId::new("t".repeat(129)).is_err());
        assert!(NetworkFunctionKind::new("n".repeat(65)).is_err());
        assert!(SessionKeyType::other("k".repeat(crate::SESSION_KEY_TYPE_MAX_BYTES + 1)).is_err());
        assert!(StableId::new(Bytes::from(vec![0xA5; crate::STABLE_ID_MAX_BYTES + 1])).is_err());
        assert!(OwnerId::new("o".repeat(crate::OWNER_ID_MAX_BYTES + 1)).is_err());
        assert!(StateType::new("s".repeat(crate::STATE_TYPE_MAX_BYTES + 1)).is_err());
        assert!(matches!(
            FencedTransitionLease::acquire(
                key(),
                OwnerId::new("v2-over-ttl").expect("owner"),
                FenceToken::new(0),
                maximum + Duration::from_nanos(1),
            ),
            Err(StoreError::InvalidSessionTtl)
        ));
    }

    #[test]
    fn v2_timestamp_range_is_fixed_independent_of_time_features() {
        let minimum = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(
                FENCED_TRANSITION_V2_MIN_TIMESTAMP_UNIX_SECONDS,
            )
            .expect("fixed V2 minimum timestamp"),
        );
        let maximum = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(
                FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS,
            )
            .expect("fixed V2 maximum timestamp"),
        );
        assert!(fenced_transition_v2_timestamp_is_in_range(minimum));
        assert!(fenced_transition_v2_timestamp_is_in_range(maximum));

        let exact = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                .expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x3C; 16]),
            FencedTransitionLease::renew(
                LeaseGuard::new(
                    key(),
                    OwnerId::new("v2-timestamp-owner").expect("owner"),
                    FenceToken::new(1),
                    Timestamp::from_offset_datetime(
                        time::OffsetDateTime::from_unix_timestamp(
                            FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS - 1,
                        )
                        .expect("maximum minus one"),
                    ),
                    maximum,
                    1,
                ),
                Duration::from_secs(1),
            )
            .expect("in-range V2 lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        );
        assert!(exact.is_ok());

        // A normal build cannot construct this timestamp. With `time`'s
        // optional large-date feature it can, and V2 still rejects it.
        if let Ok(one_over) = time::OffsetDateTime::from_unix_timestamp(
            FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS + 1,
        ) {
            let one_over = Timestamp::from_offset_datetime(one_over);
            assert!(!fenced_transition_v2_timestamp_is_in_range(one_over));
            assert!(matches!(
                FencedTransitionV2Request::new(
                    FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                        .expect("epoch"),
                    FencedTransitionV2CallerNonce::from_bytes([0x3D; 16]),
                    FencedTransitionLease::Renew {
                        lease: LeaseGuard::new(
                            key(),
                            OwnerId::new("v2-timestamp-over").expect("owner"),
                            FenceToken::new(1),
                            maximum,
                            one_over,
                            1,
                        ),
                        ttl: Duration::from_secs(1),
                    },
                    FencedTransitionMutation::delete(Generation::new(1)),
                ),
                Err(StoreError::InvalidKey(message)) if message == "fenced_transition_v2_timestamp_invalid"
            ));
        }
    }

    #[test]
    fn v2_derived_deadlines_cannot_escape_the_fixed_timestamp_range() {
        let logical_time = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(
                FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS - 1,
            )
            .expect("one second before fixed V2 maximum"),
        );
        let maximum = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(
                FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS,
            )
            .expect("fixed V2 maximum"),
        );
        let owner = OwnerId::new("v2-derived-deadline-owner").expect("owner");

        let exact_acquire = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                .expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x4A; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(1),
            )
            .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("request");
        assert_eq!(
            checked_session_deadline(logical_time, exact_acquire.lease().ttl())
                .expect("exact maximum deadline"),
            maximum
        );
        assert!(exact_acquire.validate_at(logical_time).is_ok());

        let one_over_acquire = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                .expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x4B; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(2),
            )
            .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("request");
        assert_eq!(
            one_over_acquire.validate_at(logical_time),
            Err(StoreError::InvalidSessionTtl)
        );

        let exact_renew_refresh = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                .expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x4C; 16]),
            FencedTransitionLease::renew(
                LeaseGuard::new(
                    key(),
                    owner.clone(),
                    FenceToken::new(8),
                    logical_time,
                    maximum,
                    1,
                ),
                Duration::from_secs(1),
            )
            .expect("renew"),
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(1))
                .expect("refresh"),
        )
        .expect("request");
        assert!(exact_renew_refresh.validate_at(logical_time).is_ok());

        // On a `time/large-dates` build the shared arithmetic can represent
        // this derived year-10000 deadline. V2 must reject it identically on
        // all feature graphs before follower apply or response encoding.
        let one_over_renew_refresh = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                .expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x4D; 16]),
            FencedTransitionLease::renew(
                LeaseGuard::new(key(), owner, FenceToken::new(8), logical_time, maximum, 1),
                Duration::from_secs(2),
            )
            .expect("renew"),
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(2))
                .expect("refresh"),
        )
        .expect("request");
        assert_eq!(
            one_over_renew_refresh.validate_at(logical_time),
            Err(StoreError::InvalidSessionTtl)
        );
    }

    #[test]
    fn renew_rejects_malformed_guard_profile_structurally() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x11; 16]),
            FencedTransitionLease::Renew {
                lease: LeaseGuard::new(
                    key(),
                    owner,
                    FenceToken::new(8),
                    timestamp(20),
                    timestamp(19),
                    1,
                ),
                ttl: Duration::from_secs(30),
            },
            FencedTransitionMutation::delete(Generation::new(1)),
        );

        assert!(matches!(
            request,
            Err(StoreError::InvalidKey(message)) if message == "invalid lease guard"
        ));
    }

    #[test]
    fn renew_requires_a_guard_live_at_admission() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let admission = timestamp(20);
        let request_with_expiry = |request_id, expires_at| {
            FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([request_id; 16]),
                FencedTransitionLease::renew(
                    LeaseGuard::new(
                        key(),
                        owner.clone(),
                        FenceToken::new(8),
                        timestamp(10),
                        expires_at,
                        1,
                    ),
                    Duration::from_secs(30),
                )
                .expect("structurally valid lease"),
                FencedTransitionMutation::delete(Generation::new(1)),
            )
            .expect("structurally valid request")
        };

        for (request_id, expires_at) in [(0x12, admission), (0x13, timestamp(19))] {
            assert_eq!(
                request_with_expiry(request_id, expires_at).validate_at(admission),
                Err(StoreError::LeaseExpired)
            );
        }
        assert!(request_with_expiry(0x14, timestamp(21))
            .validate_at(admission)
            .is_ok());
    }

    #[test]
    fn renew_outcome_matches_only_a_guard_live_at_recorded_time() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let recorded_at = timestamp(20);
        let request_with_expiry = |request_id, expires_at| {
            FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([request_id; 16]),
                FencedTransitionLease::renew(
                    LeaseGuard::new(
                        key(),
                        owner.clone(),
                        FenceToken::new(8),
                        timestamp(10),
                        expires_at,
                        1,
                    ),
                    Duration::from_secs(30),
                )
                .expect("structurally valid lease"),
                FencedTransitionMutation::delete(Generation::new(1)),
            )
            .expect("structurally valid request")
        };
        let outcome = FencedTransitionOutcome::new(
            LeaseGuard::new(
                key(),
                owner.clone(),
                FenceToken::new(8),
                timestamp(10),
                checked_session_deadline(recorded_at, Duration::from_secs(30))
                    .expect("renewed lease expiry"),
                1,
            ),
            Generation::new(1),
            FencedTransitionMutationResult::Deleted,
            recorded_at,
        )
        .expect("valid outcome shape");

        assert!(outcome.matches_request(&request_with_expiry(0x15, timestamp(21))));
        assert!(!outcome.matches_request(&request_with_expiry(0x16, recorded_at)));
    }

    #[test]
    fn request_identity_must_not_be_all_zeroes() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease action"),
            FencedTransitionMutation::create(record(key(), owner, FenceToken::new(8), 1)),
        );
        assert!(matches!(
            request,
            Err(StoreError::InvalidKey(message)) if message == INVALID_TRANSITION_REQUEST_ID
        ));
    }

    #[test]
    fn acquire_cannot_refresh_an_old_fenced_record() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([6; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease action"),
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
                .expect("mutation"),
        );
        assert!(matches!(
            request,
            Err(StoreError::InvalidKey(message))
                if message == INVALID_TRANSITION_REFRESH_ACQUIRE
        ));

        let renewed = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([7; 16]),
            FencedTransitionLease::renew(
                lease_guard(key(), owner, FenceToken::new(8)),
                Duration::from_secs(30),
            )
            .expect("lease action"),
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
                .expect("mutation"),
        );
        assert!(renewed.is_ok());
    }

    #[test]
    fn outcome_retention_is_exactly_one_day() {
        let recorded_at = timestamp(10);
        let outcome = FencedTransitionOutcome::new(
            lease_guard(
                key(),
                OwnerId::new("owner-a").expect("owner"),
                FenceToken::new(8),
            ),
            Generation::new(1),
            FencedTransitionMutationResult::Created,
            recorded_at,
        )
        .expect("outcome");
        let expected = checked_session_deadline(recorded_at, FENCED_TRANSITION_OUTCOME_RETENTION)
            .expect("retention deadline");
        assert_eq!(outcome.retained_until(), expected);
        assert!(!outcome.is_expired_at(timestamp(10)));
        assert!(outcome.is_expired_at(expected));
        assert_eq!(
            format!("{outcome:?}"),
            "FencedTransitionOutcome(<redacted>)"
        );

        let too_late = Timestamp::from_offset_datetime(
            *expected.as_offset_datetime() + time::Duration::nanoseconds(1),
        );
        let invalid = FencedTransitionOutcome {
            lease: outcome.lease.clone(),
            committed_generation: outcome.committed_generation,
            mutation: outcome.mutation,
            recorded_at,
            retained_until: too_late,
        };
        assert!(matches!(
            invalid.validate(),
            Err(StoreError::Serialization(_))
        ));
    }

    #[test]
    fn public_outcome_validation_uses_the_outcome_recorded_time() {
        let recorded_at = timestamp(10);
        let owner = OwnerId::new("outcome-validation-owner").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x44; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::create(record(key(), owner.clone(), FenceToken::new(8), 1)),
        )
        .expect("request");
        let outcome = FencedTransitionOutcome::new(
            LeaseGuard::new(
                key(),
                owner,
                FenceToken::new(8),
                recorded_at,
                checked_session_deadline(recorded_at, Duration::from_secs(30)).expect("expiry"),
                1,
            ),
            Generation::new(1),
            FencedTransitionMutationResult::Created,
            recorded_at,
        )
        .expect("outcome");
        assert!(outcome.matches_request(&request));
    }

    #[test]
    fn outcome_time_envelopes_accept_exact_maximum_and_reject_one_over() {
        let recorded_at = timestamp(10);
        let exact_maximum = checked_session_deadline(recorded_at, crate::MAX_SESSION_TTL)
            .expect("maximum outcome deadline");
        let one_over = Timestamp::from_offset_datetime(
            exact_maximum
                .as_offset_datetime()
                .checked_add(time::Duration::nanoseconds(1))
                .expect("one-over outcome deadline"),
        );
        let retained_until =
            checked_session_deadline(recorded_at, FENCED_TRANSITION_OUTCOME_RETENTION)
                .expect("retention deadline");
        let make_outcome = |acquired_at, lease_expires_at, mutation| FencedTransitionOutcome {
            lease: LeaseGuard::new(
                key(),
                OwnerId::new("owner-a").expect("owner"),
                FenceToken::new(8),
                acquired_at,
                lease_expires_at,
                1,
            ),
            committed_generation: Generation::new(1),
            mutation,
            recorded_at,
            retained_until,
        };

        assert!(make_outcome(
            recorded_at,
            exact_maximum,
            FencedTransitionMutationResult::TtlRefreshed {
                expires_at: exact_maximum,
            },
        )
        .validate()
        .is_ok());
        for invalid in [
            make_outcome(
                recorded_at,
                one_over,
                FencedTransitionMutationResult::Created,
            ),
            make_outcome(
                recorded_at,
                exact_maximum,
                FencedTransitionMutationResult::TtlRefreshed {
                    expires_at: one_over,
                },
            ),
            make_outcome(
                Timestamp::from_offset_datetime(
                    recorded_at
                        .as_offset_datetime()
                        .checked_add(time::Duration::nanoseconds(1))
                        .expect("future acquisition"),
                ),
                exact_maximum,
                FencedTransitionMutationResult::Created,
            ),
            make_outcome(
                recorded_at,
                exact_maximum,
                FencedTransitionMutationResult::TtlRefreshed {
                    expires_at: recorded_at,
                },
            ),
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(StoreError::Serialization(_))
            ));
        }
    }

    #[test]
    fn maximum_typed_outcome_serialization_is_below_the_outcome_cap() {
        // Every variable-width member of an outcome is in its lease key or
        // owner. This fixture uses each public maximum, plus scalar values
        // whose JSON renderings are maximal, to show that a typed outcome
        // cannot approach the 16 KiB cap without adding a payload field.
        // 9999-12-30T00:00:00Z leaves the fixed 24-hour receipt window
        // representable while maximizing the timestamp's JSON width.
        let recorded_at = timestamp(253_402_128_000);
        let lease = LeaseGuard::new(
            SessionKey {
                tenant: TenantId::new("t".repeat(128)).expect("maximum tenant"),
                nf_kind: NetworkFunctionKind::new("n".repeat(64)).expect("maximum NF kind"),
                key_type: SessionKeyType::other("k".repeat(crate::SESSION_KEY_TYPE_MAX_BYTES))
                    .expect("maximum key type"),
                stable_id: StableId::new(Bytes::from(vec![u8::MAX; crate::STABLE_ID_MAX_BYTES]))
                    .expect("maximum stable ID"),
            },
            OwnerId::new("o".repeat(crate::OWNER_ID_MAX_BYTES)).expect("maximum owner"),
            FenceToken::new(u64::MAX),
            recorded_at,
            Timestamp::from_offset_datetime(
                *recorded_at.as_offset_datetime() + time::Duration::nanoseconds(1),
            ),
            u64::MAX,
        );
        let outcome = FencedTransitionOutcome::new(
            lease,
            Generation::new(u64::MAX),
            FencedTransitionMutationResult::TtlRefreshed {
                expires_at: Timestamp::from_offset_datetime(
                    *recorded_at.as_offset_datetime() + time::Duration::nanoseconds(1),
                ),
            },
            recorded_at,
        )
        .expect("maximum typed outcome remains valid");
        let encoded = serde_json::to_vec(&outcome).expect("serialize maximum typed outcome");

        assert!(
            encoded.len() < FENCED_TRANSITION_MAX_OUTCOME_BYTES,
            "maximum typed outcome is {} bytes, below the {} byte cap",
            encoded.len(),
            FENCED_TRANSITION_MAX_OUTCOME_BYTES,
        );
        assert!(outcome.validate().is_ok());
    }

    #[test]
    fn debug_output_is_non_identifying() {
        let request_id = FencedTransitionRequestId::from_bytes([0x5a; 16]);
        assert_eq!(
            format!("{request_id:?}"),
            "FencedTransitionRequestId(<redacted>)"
        );
        assert!(!format!("{request_id:?}").contains("5a"));
        assert_eq!(
            format!(
                "{:?}",
                FencedTransitionMutationResult::TtlRefreshed {
                    expires_at: timestamp(123),
                }
            ),
            "FencedTransitionMutationResult(<redacted>)"
        );
        assert_eq!(
            format!(
                "{:?}",
                FencedTransitionStatus::Recorded(Box::new(Err(StoreError::InvalidKey(
                    "secret".into(),
                ))))
            ),
            "FencedTransitionStatus(<redacted>)"
        );

        let mut debug_key = key();
        debug_key.tenant = TenantId::from_static("debug-secret-tenant");
        let debug_owner = OwnerId::new("debug-secret-owner").expect("owner");
        let debug_lease = FencedTransitionLease::acquire(
            debug_key.clone(),
            debug_owner.clone(),
            FenceToken::new(90),
            Duration::from_secs(30),
        )
        .expect("lease action");
        let debug_mutation = FencedTransitionMutation::create(record(
            debug_key.clone(),
            debug_owner,
            FenceToken::new(91),
            1,
        ));
        let debug_request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0xA5; 16]),
            debug_lease.clone(),
            debug_mutation.clone(),
        )
        .expect("request");
        let debug_observation =
            FencedTransitionObservation::new(debug_mutation.record().cloned(), FenceToken::new(91))
                .expect("observation");
        let rendered =
            format!("{debug_lease:?}{debug_mutation:?}{debug_request:?}{debug_observation:?}");
        let rendered_lower = rendered.to_ascii_lowercase();
        for secret in ["debug-secret", "90", "91", "a5", "opaque"] {
            assert!(!rendered_lower.contains(secret));
        }
        assert_eq!(
            [
                StoreError::FencedTransitionRequestConflict,
                StoreError::FencedTransitionOutcomeUnknown,
                StoreError::FencedTransitionRequestExpired,
                StoreError::FencedTransitionHistoryFull,
                StoreError::FencedTransitionRetentionExhausted,
                StoreError::FencedTransitionStorageExhausted,
            ]
            .map(|error| error.to_string()),
            [
                "fenced transition request identity was reused",
                "fenced transition outcome is unknown",
                "fenced transition result retention expired",
                "fenced transition request history is full",
                "fenced transition result retention horizon is exhausted",
                "fenced transition storage counter is exhausted",
            ]
            .map(str::to_owned)
        );
    }

    #[test]
    fn status_recorded_result_is_compact_and_serialization_transparent() {
        let status = FencedTransitionStatus::Recorded(Box::new(Err(StoreError::NotFound)));

        assert!(
            std::mem::size_of::<FencedTransitionStatus>()
                < std::mem::size_of::<FencedTransitionOutcome>(),
            "the status must not inline a complete outcome"
        );
        assert_eq!(
            serde_json::to_string(&status).expect("serialize status"),
            r#"{"Recorded":{"Err":"NotFound"}}"#,
            "boxing must not change the externally tagged persisted status shape"
        );
        assert_eq!(
            serde_json::from_str::<FencedTransitionStatus>(r#"{"Recorded":{"Err":"NotFound"}}"#,)
                .expect("deserialize legacy recorded status"),
            status,
        );
    }

    #[test]
    fn v2_retention_exhausted_status_is_append_only_and_wire_visible() {
        assert_eq!(
            serde_json::to_string(&FencedTransitionV2Status::RetentionExhausted)
                .expect("serialize status"),
            r#""RetentionExhausted""#,
            "V2 status names are persisted and the new terminal state is explicit"
        );
    }

    #[test]
    fn v2_id_is_deterministic_and_commits_the_complete_body() {
        let owner = OwnerId::new("v2-owner").expect("owner");
        let epoch = FencedTransitionV2HistoryEpoch::new(7).expect("nonzero epoch");
        let nonce = FencedTransitionV2CallerNonce::from_bytes([0xA1; 16]);
        let lease = FencedTransitionLease::acquire(
            key(),
            owner.clone(),
            FenceToken::new(7),
            Duration::from_secs(30),
        )
        .expect("lease");
        let mutation =
            FencedTransitionMutation::create(record(key(), owner, FenceToken::new(8), 1));

        let first = FencedTransitionV2Request::new(epoch, nonce, lease.clone(), mutation.clone())
            .expect("request");
        let retry = FencedTransitionV2Request::new(epoch, nonce, lease.clone(), mutation)
            .expect("stable retry");
        let changed = FencedTransitionV2Request::new(
            epoch,
            nonce,
            lease.clone(),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("another valid body");

        assert_eq!(first.request_id(), retry.request_id());
        assert_ne!(first.request_id(), changed.request_id());
        assert_eq!(
            first.request_id().to_bytes().len(),
            FENCED_TRANSITION_V2_REQUEST_ID_BYTES
        );
        assert_eq!(first.request_id().epoch(), epoch);
        assert_eq!(first.request_id().nonce(), nonce);
        assert!(first.validate().is_ok());

        let substituted = FencedTransitionV2Request::from_parts(
            first.request_id(),
            lease,
            FencedTransitionMutation::delete(Generation::new(1)),
        );
        assert_eq!(
            substituted,
            Err(StoreError::FencedTransitionRequestConflict),
            "a body changed under an existing full ID is closed even after receipt reclamation"
        );

        let invalid_substitution = FencedTransitionV2Request::from_parts(
            first.request_id(),
            FencedTransitionLease::Acquire {
                key: key(),
                owner: OwnerId::new("different-owner").expect("owner"),
                expected_fence: FenceToken::new(7),
                ttl: Duration::ZERO,
            },
            FencedTransitionMutation::delete(Generation::new(1)),
        );
        assert_eq!(
            invalid_substitution,
            Err(StoreError::FencedTransitionRequestConflict),
            "commitment mismatch is classified before substituted-body validation"
        );
    }

    #[test]
    fn v2_canonical_body_vector_material() {
        let owner = OwnerId::new("v2-vector-owner").expect("owner");
        let epoch = FencedTransitionV2HistoryEpoch::new(7).expect("epoch");
        let guard = lease_guard(key(), owner.clone(), FenceToken::new(8));
        let acquire_create = (
            FencedTransitionV2CallerNonce::from_bytes([0xA1; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::create(record(key(), owner.clone(), FenceToken::new(8), 1)),
        );
        let mut update_record = record(key(), owner.clone(), FenceToken::new(8), 2);
        update_record.expires_at = Some(timestamp(200));
        update_record.payload = EncryptedSessionPayload::legacy_plaintext(b"legacy");
        let renew_update = (
            FencedTransitionV2CallerNonce::from_bytes([0xB2; 16]),
            FencedTransitionLease::renew(guard.clone(), Duration::new(31, 9)).expect("lease"),
            FencedTransitionMutation::update(Generation::new(1), update_record),
        );
        let renew_delete = (
            FencedTransitionV2CallerNonce::from_bytes([0xC3; 16]),
            FencedTransitionLease::renew(guard.clone(), Duration::new(32, 10)).expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        );
        let renew_refresh = (
            FencedTransitionV2CallerNonce::from_bytes([0xD4; 16]),
            FencedTransitionLease::renew(guard, Duration::new(33, 11)).expect("lease"),
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::new(40, 12))
                .expect("mutation"),
        );

        for (label, nonce, lease, mutation) in [
            (
                "acquire-create",
                acquire_create.0,
                acquire_create.1,
                acquire_create.2,
            ),
            (
                "renew-update",
                renew_update.0,
                renew_update.1,
                renew_update.2,
            ),
            (
                "renew-delete",
                renew_delete.0,
                renew_delete.1,
                renew_delete.2,
            ),
            (
                "renew-refresh",
                renew_refresh.0,
                renew_refresh.1,
                renew_refresh.2,
            ),
        ] {
            let body = v2_canonical_body(&lease, &mutation);
            let request = FencedTransitionV2Request::new(epoch, nonce, lease, mutation)
                .expect("valid request");
            let (expected_body, expected_commitment, expected_id, expected_outer_id) = match label {
                "acquire-create" => (
                    "010121000000000000001766656e6365642d7472616e736974696f6e2d6d6f64656c0000000000000003736d660200000000000000096f70617175652d6964000000000000000f76322d766563746f722d6f776e65720000000000000007000000000000001e00000000112321000000000000001766656e6365642d7472616e736974696f6e2d6d6f64656c0000000000000003736d660200000000000000096f70617175652d69640000000000000001000000000000000f76322d766563746f722d6f776e6572000000000000000801000000000000000c6f70617175652d7374617465000100000000000000066f7061717565",
                    "10552600c94acd9fec33d5baff5a25ccf50ebd6cee6a39a756444c688abcebb7",
                    "0000000000000007a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a110552600c94acd9fec33d5baff5a25ccf50ebd6cee6a39a756444c688abcebb7",
                    "3e716e6fa3f3401c908e45f20dadd3f3",
                ),
                "renew-update" => (
                    "01022221000000000000001766656e6365642d7472616e736974696f6e2d6d6f64656c0000000000000003736d660200000000000000096f70617175652d6964000000000000000f76322d766563746f722d6f776e65720000000000000008000000000000000a000000000000000000000046000000000000000000000001000000000000001f000000091200000000000000012321000000000000001766656e6365642d7472616e736974696f6e2d6d6f64656c0000000000000003736d660200000000000000096f70617175652d69640000000000000002000000000000000f76322d766563746f722d6f776e6572000000000000000801000000000000000c6f70617175652d73746174650100000000000000c8000000000200000000000000066c6567616379",
                    "44aebe69e4b1d75b86a2d53926b9251019fb7a15f0558f7ea571f4228744c5cb",
                    "0000000000000007b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b244aebe69e4b1d75b86a2d53926b9251019fb7a15f0558f7ea571f4228744c5cb",
                    "c323dfc72755df96e47f0998bcec66e1",
                ),
                "renew-delete" => (
                    "01022221000000000000001766656e6365642d7472616e736974696f6e2d6d6f64656c0000000000000003736d660200000000000000096f70617175652d6964000000000000000f76322d766563746f722d6f776e65720000000000000008000000000000000a00000000000000000000004600000000000000000000000100000000000000200000000a130000000000000001",
                    "e9ba9474f0f02e71100831ad2b0af8ce5f7aacc62804807afe0d114934b78dbe",
                    "0000000000000007c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3e9ba9474f0f02e71100831ad2b0af8ce5f7aacc62804807afe0d114934b78dbe",
                    "13cae18bf9db78540bf517cc7409b7af",
                ),
                "renew-refresh" => (
                    "01022221000000000000001766656e6365642d7472616e736974696f6e2d6d6f64656c0000000000000003736d660200000000000000096f70617175652d6964000000000000000f76322d766563746f722d6f776e65720000000000000008000000000000000a00000000000000000000004600000000000000000000000100000000000000210000000b14000000000000000100000000000000280000000c",
                    "ddcd848d0923330a9824ff902ef00f413139e90be4207fc9ff27e28661722009",
                    "0000000000000007d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4ddcd848d0923330a9824ff902ef00f413139e90be4207fc9ff27e28661722009",
                    "0cf8fcc40300caafa5cb2fc167d33ca0",
                ),
                _ => unreachable!("fixed test vector label"),
            };
            assert_eq!(
                crate::hex::encode_lower(&body),
                expected_body,
                "{label} pins the direct frozen encoder bytes independently of serde"
            );
            assert_eq!(
                crate::hex::encode_lower(request.request_id().body_commitment()),
                expected_commitment,
                "{label} request commitment"
            );
            assert_eq!(
                crate::hex::encode_lower(&request.request_id().to_bytes()),
                expected_id,
                "{label} full request ID"
            );
            assert_eq!(
                crate::hex::encode_lower(&fenced_transition_v2_outer_request_id(
                    request.request_id()
                )),
                expected_outer_id,
                "{label} full-ID-derived outer consensus identity"
            );
        }
    }

    #[test]
    fn v2_request_roundtrips_and_revalidates_its_commitment() {
        let owner = OwnerId::new("v2-owner").expect("owner");
        let request = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(9).expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0xB2; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::create(record(key(), owner, FenceToken::new(8), 1)),
        )
        .expect("request");

        let encoded = serde_json::to_string(&request).expect("serialize");
        let decoded: FencedTransitionV2Request = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, request);
        assert_eq!(
            decoded.recomputed_body_commitment().expect("commitment"),
            *decoded.request_id().body_commitment()
        );
        assert!(decoded.validate().is_ok());
        assert!(serde_json::from_str::<FencedTransitionV2Request>(&format!(
            "{{\"unexpected\":true,{}}}",
            &encoded[1..]
        ))
        .is_err());
    }

    #[test]
    fn v2_request_serde_materializes_invalid_body_before_commitment_conflict() {
        let request = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(9).expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0xB3; 16]),
            FencedTransitionLease::acquire(
                key(),
                OwnerId::new("v2-conflict-owner").expect("owner"),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("request");

        let invalid_lease = FencedTransitionLease::Acquire {
            key: key(),
            owner: OwnerId::new("v2-conflict-owner").expect("owner"),
            expected_fence: FenceToken::new(7),
            ttl: Duration::ZERO,
        };
        let mut encoded = serde_json::to_value(&request).expect("serialize");
        encoded["lease"] = serde_json::to_value(&invalid_lease).expect("invalid body wire form");
        let decoded: FencedTransitionV2Request = serde_json::from_value(encoded.clone())
            .expect("same-ID invalid body must materialize from JSON");
        assert!(matches!(
            decoded.validate(),
            Err(StoreError::FencedTransitionRequestConflict)
        ));

        let postcard = opc_consensus::encode_bounded(&decoded).expect("encode invalid retry");
        let postcard_decoded: FencedTransitionV2Request =
            opc_consensus::decode_bounded(&postcard).expect("same-ID invalid body from Postcard");
        assert!(matches!(
            postcard_decoded.validate(),
            Err(StoreError::FencedTransitionRequestConflict)
        ));

        let mut matching_id_invalid = encoded;
        matching_id_invalid["request_id"]["body_commitment"] = serde_json::to_value(
            v2_body_commitment(
                request.request_id().epoch(),
                request.request_id().nonce(),
                &invalid_lease,
                request.mutation(),
            )
            .expect("commitment for representable invalid body"),
        )
        .expect("commitment wire form");
        let matching_id_invalid: FencedTransitionV2Request =
            serde_json::from_value(matching_id_invalid)
                .expect("matching-ID invalid body must materialize for ingress validation");
        assert!(matches!(
            matching_id_invalid.validate(),
            Err(StoreError::InvalidSessionTtl)
        ));
    }

    #[test]
    fn v2_epoch_zero_is_rejected() {
        assert_eq!(
            FencedTransitionV2HistoryEpoch::new(0),
            Err(StoreError::InvalidKey(
                INVALID_TRANSITION_V2_HISTORY_EPOCH.into()
            ))
        );
        assert!(serde_json::from_str::<FencedTransitionV2HistoryEpoch>("0").is_err());
        assert_eq!(
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH)
                .expect("signed durable maximum")
                .get(),
            FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH
        );
        assert!(
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH + 1)
                .is_err()
        );
    }

    #[test]
    fn v2_constants_leave_required_headroom_and_profile_is_fixed() {
        assert_eq!(FENCED_TRANSITION_SCHEMA_V2, 2);
        assert_eq!(FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES, 131_072);
        assert_eq!(FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET, 100_000);
        assert_eq!(FENCED_TRANSITION_V2_RECLAIM_BATCH, 1_024);
        assert_eq!(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH, 1);
        assert_eq!(FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH, i64::MAX as u64);
        assert_eq!(FENCED_TRANSITION_V2_MAX_DURABLE_GENERATION, i64::MAX as u64);
        assert_eq!(FENCED_TRANSITION_V2_RECEIPT_RESPONSE_MAX_BYTES, 17_408);
        assert_eq!(
            FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_MAGIC,
            *b"OPCFV2R1"
        );
        assert_eq!(FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_REVISION, 1);
        assert_eq!(FENCED_TRANSITION_V2_VALIDATION_SCHEMA_REVISION, 1);
        assert_eq!(FENCED_TRANSITION_V2_COMMAND_TRANSPORT_SCHEMA_REVISION, 1);
        assert_eq!(FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION, 1);
        assert_eq!(
            FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES,
            2 * 1024 * 1024
        );
        assert_eq!(
            FENCED_TRANSITION_V2_MIN_DURABLE_LOG_ENTRY_BYTES,
            16 * 1024 * 1024
        );
        assert_eq!(
            FENCED_TRANSITION_V2_COMMAND_TRANSPORT_PROFILE_INPUTS,
            [1, 2 * 1024 * 1024, 16 * 1024 * 1024]
        );
        assert_eq!(FENCED_TRANSITION_V2_RECORD_ENVELOPE_SCHEMA_REVISION, 1);
        assert_eq!(FENCED_TRANSITION_V2_RETENTION_PROFILE_INPUTS, [86_400, 0]);
        assert_eq!(
            FENCED_TRANSITION_V2_VALIDATION_PROFILE_INPUTS,
            [
                31_536_000,
                0,
                0,
                0,
                128,
                64,
                1,
                64,
                128,
                128,
                128,
                FENCED_TRANSITION_V2_MIN_TIMESTAMP_UNIX_SECONDS as u64,
                FENCED_TRANSITION_V2_MAX_TIMESTAMP_UNIX_SECONDS as u64,
                999_999_999,
                1,
                i64::MAX as u64,
                1_048_576,
                u32::MAX as u64,
            ]
        );
        assert_eq!(FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_REVISION, 1);
        assert_eq!(FENCED_TRANSITION_V2_ERROR_STATUS_REVISION, 2);
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.contains("body=version:u8=1"));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR
            .contains("ingress=validate-commitment-before-semantic-validation"));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.contains("outer-id="));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.contains("validation=see:"));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.contains("command-transport=see:"));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.contains("record-envelope=see:"));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR
            .contains("outcome-retention=secs-u64be+nanos-u64be"));
        assert!(
            FENCED_TRANSITION_V2_COMMAND_TRANSPORT_SCHEMA_DESCRIPTOR.contains("rpc=postcard-1.1.3")
        );
        assert!(FENCED_TRANSITION_V2_RECORD_ENVELOPE_SCHEMA_DESCRIPTOR
            .contains("envelope=magic:OPCE:bytes4,version:u16be=1"));
        assert!(FENCED_TRANSITION_V2_VALIDATION_SCHEMA_DESCRIPTOR
            .contains("payload-capacity=exact-max-record-payload-bytes"));
        assert!(FENCED_TRANSITION_V2_VALIDATION_SCHEMA_DESCRIPTOR
            .contains("derived-deadlines=lease-and-refresh"));
        assert_eq!(FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES, 1_048_576);
        assert_eq!(
            FENCED_TRANSITION_V2_MAX_PAYLOAD_TOO_LARGE_ACTUAL_BYTES,
            u32::MAX as u64
        );
        assert!(
            FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_SCHEMA_DESCRIPTOR
                .contains("24:payload-too-large")
        );
        assert!(
            FENCED_TRANSITION_V2_RECEIPT_RESPONSE_CODEC_SCHEMA_DESCRIPTOR
                .contains("25:storage-exhausted")
        );
        assert!(
            FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_DESCRIPTOR.contains("history-format=3")
        );
        assert!(FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_DESCRIPTOR
            .contains("capacity=active-epoch-receipts<=131072"));
        assert!(FENCED_TRANSITION_V2_PERSISTED_HISTORY_SCHEMA_DESCRIPTOR
            .contains("generation:u64be<=durable-counter-max"));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.contains("replicated-command-wire="));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.contains(
            "lease-postcard[acquire:0,renew:1],mutation-postcard[create:0,update:1,delete:2,refresh-ttl:3]"
        ));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.contains(
            "state-class-postcard[authoritative-session:0,dataplane-lookup:1,replicated-dr:2,telemetry-derived:3,ephemeral-procedure:4]"
        ));
        assert!(FENCED_TRANSITION_V2_PROFILE_SCHEMA_DESCRIPTOR.contains(
            "payload-encoding-postcard[plaintext:0,legacy-plaintext:1,envelope-v1:2,unclassified:3]"
        ));
        assert_ne!(
            fenced_transition_v2_profile_digest_with_outcome_retention(Duration::from_secs(86_400)),
            fenced_transition_v2_profile_digest_with_outcome_retention(
                Duration::from_secs(86_400) + Duration::from_nanos(1)
            ),
            "a nanos-only retention change must advertise a distinct V2 profile"
        );
        const {
            assert!(
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                    >= FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET
                        + FENCED_TRANSITION_V2_RECLAIM_BATCH
            );
        }
        assert_eq!(
            fenced_transition_v2_profile_digest(),
            [
                0x0f, 0x51, 0xdb, 0x98, 0xa6, 0x69, 0x18, 0xc0, 0xb8, 0x27, 0xf7, 0x6a, 0x5d, 0xcf,
                0xd1, 0x98, 0x23, 0x0f, 0x15, 0x8f, 0xce, 0xab, 0x0b, 0x91, 0xe1, 0x2e, 0xe9, 0xca,
                0x47, 0x2a, 0x08, 0x4c,
            ],
            "changing V2's pinned semantics requires a new advertised profile digest"
        );
    }

    #[test]
    fn v2_history_state_exposes_safe_rotation_and_reclaim_progress() {
        let active = FencedTransitionV2HistoryEpoch::new(3).expect("epoch");
        let retired = FencedTransitionV2HistoryEpoch::new(2).expect("epoch");
        let active_state = FencedTransitionV2HistoryState::new(
            Some(active),
            Some(retired),
            None,
            0,
            11,
            FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET,
            12,
        )
        .expect("active state");
        assert_eq!(active_state.active_epoch(), Some(active));
        assert_eq!(active_state.retired_through(), Some(retired));
        assert_eq!(active_state.reclaim_epoch(), None);
        assert_eq!(active_state.reclaim_remaining(), 0);
        assert_eq!(active_state.generation(), 11);
        assert_eq!(active_state.bound_entries(), 100_000);
        assert_eq!(active_state.reclaimed_entries(), 12);

        let reclaiming = FencedTransitionV2HistoryState::new(
            None,
            Some(retired),
            Some(retired),
            FENCED_TRANSITION_V2_RECLAIM_BATCH,
            12,
            0,
            100_000,
        )
        .expect("reclaiming state");
        assert_eq!(reclaiming.reclaim_epoch(), Some(retired));
        assert_eq!(
            reclaiming.reclaim_remaining(),
            FENCED_TRANSITION_V2_RECLAIM_BATCH
        );
        assert!(FencedTransitionV2HistoryState::new(
            Some(active),
            Some(retired),
            Some(retired),
            1,
            12,
            0,
            100_000,
        )
        .is_err());
    }

    #[test]
    fn v2_history_state_serde_is_fixed_width_and_revalidates_lifecycle() {
        let initial = FencedTransitionV2HistoryState::new(
            Some(
                FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                    .expect("initial epoch"),
            ),
            None,
            None,
            0,
            1,
            0,
            0,
        )
        .expect("initial history state");
        assert_eq!(
            serde_json::to_string(&initial).expect("serialize history state"),
            r#"{"active_epoch":1,"retired_through":null,"reclaim_epoch":null,"reclaim_remaining":0,"generation":1,"bound_entries":0,"reclaimed_entries":0}"#,
            "history counts are frozen u64 fields in a stable public shape"
        );
        assert_eq!(
            serde_json::from_str::<FencedTransitionV2HistoryState>(
                r#"{"active_epoch":1,"retired_through":null,"reclaim_epoch":null,"reclaim_remaining":0,"generation":1,"bound_entries":0,"reclaimed_entries":0}"#,
            )
            .expect("decode valid state"),
            initial
        );
        for malformed in [
            r#"{"active_epoch":1,"retired_through":null,"reclaim_epoch":1,"reclaim_remaining":1,"generation":1,"bound_entries":0,"reclaimed_entries":0}"#,
            r#"{"active_epoch":1,"retired_through":null,"reclaim_epoch":null,"reclaim_remaining":0,"generation":1,"bound_entries":131073,"reclaimed_entries":0}"#,
            r#"{"active_epoch":null,"retired_through":1,"reclaim_epoch":1,"reclaim_remaining":18446744073709551615,"generation":1,"bound_entries":0,"reclaimed_entries":0}"#,
            r#"{"active_epoch":1,"retired_through":null,"reclaim_epoch":null,"reclaim_remaining":0,"generation":1,"bound_entries":0,"reclaimed_entries":0,"unexpected":true}"#,
        ] {
            assert!(
                serde_json::from_str::<FencedTransitionV2HistoryState>(malformed).is_err(),
                "malformed durable history state must not bypass constructor validation"
            );
        }
    }

    #[test]
    fn v2_history_state_generation_is_durable_i64_bounded() {
        let active = Some(
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                .expect("initial epoch"),
        );
        let at_max = FencedTransitionV2HistoryState::new(
            active,
            None,
            None,
            0,
            FENCED_TRANSITION_V2_MAX_DURABLE_GENERATION,
            0,
            0,
        )
        .expect("largest SQLite-portable generation");
        assert_eq!(
            at_max.generation(),
            FENCED_TRANSITION_V2_MAX_DURABLE_GENERATION
        );
        assert!(FencedTransitionV2HistoryState::new(
            active,
            None,
            None,
            0,
            FENCED_TRANSITION_V2_MAX_DURABLE_GENERATION + 1,
            0,
            0,
        )
        .is_err());

        let encoded = serde_json::to_value(at_max).expect("fixed-width state wire");
        assert_eq!(
            serde_json::from_value::<FencedTransitionV2HistoryState>(encoded.clone())
                .expect("max generation wire state"),
            at_max
        );
        let mut one_over = encoded;
        one_over["generation"] =
            serde_json::Value::from(FENCED_TRANSITION_V2_MAX_DURABLE_GENERATION + 1);
        assert!(serde_json::from_value::<FencedTransitionV2HistoryState>(one_over).is_err());
    }

    #[test]
    fn v2_history_state_rejects_corrupt_epoch_lifecycle_progress() {
        let epoch_one =
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                .expect("epoch");
        let epoch_two = FencedTransitionV2HistoryEpoch::new(2).expect("epoch");
        let epoch_three = FencedTransitionV2HistoryEpoch::new(3).expect("epoch");
        let maximum_epoch =
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_MAX_HISTORY_EPOCH)
                .expect("epoch");

        for state in [
            // An initialized history cannot have neither an active nor a reclaim epoch.
            FencedTransitionV2HistoryState::new(None, None, None, 0, 1, 0, 0),
            // The first active epoch is exactly one.
            FencedTransitionV2HistoryState::new(Some(epoch_two), None, None, 0, 1, 0, 0),
            // Active epochs do not carry in-progress reclaim work.
            FencedTransitionV2HistoryState::new(Some(epoch_one), None, None, 1, 1, 0, 0),
            // Rotation must open the immediate successor, never leave a gap.
            FencedTransitionV2HistoryState::new(
                Some(epoch_three),
                Some(epoch_one),
                None,
                0,
                1,
                0,
                0,
            ),
            // A saturated retired epoch has no representable next active epoch.
            FencedTransitionV2HistoryState::new(
                Some(maximum_epoch),
                Some(maximum_epoch),
                None,
                0,
                1,
                0,
                0,
            ),
            // Reclaim targets exactly the retired floor and has no active bindings.
            FencedTransitionV2HistoryState::new(None, Some(epoch_two), Some(epoch_one), 1, 1, 0, 0),
            FencedTransitionV2HistoryState::new(None, Some(epoch_two), Some(epoch_two), 1, 1, 1, 0),
            // A reclaim operation is never empty or beyond the physical cap.
            FencedTransitionV2HistoryState::new(None, Some(epoch_two), Some(epoch_two), 0, 1, 0, 0),
            FencedTransitionV2HistoryState::new(
                None,
                Some(epoch_two),
                Some(epoch_two),
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES + 1,
                1,
                0,
                0,
            ),
        ] {
            assert!(state.is_err());
        }
    }
}
