//! Proposed joint action-16 payload. No retained mode opens or applies it yet.
//!
//! Existing target9 serde refuses the appended tag before allocating a record.
//! This separate input schema bounds every variable owner and rejects unknown
//! nested fields without changing any legacy or bounded8 input acceptance.

use std::fmt;
use std::sync::Arc;

use opc_crypto::{
    ConfigCapacityProfile, ConfigPreparationPool, ConfigPreparationReservation,
    CONFIG_CAPACITY_V1_ENVELOPE_BYTES,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    PreparedTargetMutation, TargetActionV1, TargetEffectV1, TargetExpectationV1,
    TargetLockExpectationV1, TargetPayloadV1, TargetResolutionV1, TargetSourceV1,
};
use crate::audit_authority::{AuditAuthorityError, AuditCaller, AuditOperationHandle, AuditToken};
use crate::consensus::capacity_record::{CapacityRecordBinding, PreparedCapacityCommit};
use crate::consensus::config_capacity_decode::{json_string_preflight, reserve_next, Bytes, Text};
use crate::consensus::preparation::PreparationOwnership;
use crate::consensus::types::{
    CONFIG_AUDIT_PATH_MAX_BYTES, CONFIG_CAPACITY_V1_METADATA_BYTES, CONFIG_PRINCIPAL_MAX_BYTES,
};
use crate::consensus::{ConfigConsensusIdentity, PreparedConfigCommit};
use crate::{AuditKey, AuditRecord, CommitRecord};

#[derive(PartialEq, Serialize)]
#[serde(rename = "BoundedRunningPayloadV1")]
struct PayloadFields {
    commit: PreparedConfigCommit,
    binding: CapacityRecordBinding,
}

/// One immutable ciphertext/proof pair. No preparation owner enters a command
/// or retained log clone. The surrounding preparation owns the actual slot.
#[derive(Clone)]
pub(crate) struct BoundedRunningPayload {
    fields: Arc<PayloadFields>,
}

impl PartialEq for BoundedRunningPayload {
    fn eq(&self, other: &Self) -> bool {
        self.fields == other.fields
    }
}

impl Serialize for BoundedRunningPayload {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.fields.as_ref().serialize(serializer)
    }
}

// This is representation only. The old TargetPayloadV1 deliberately skips
// this variant; joint input still receives no preparation or audit authority.
impl<'de> Deserialize<'de> for BoundedRunningPayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        PayloadInput::deserialize(deserializer).map(Into::into)
    }
}

impl BoundedRunningPayload {
    pub(in crate::consensus) fn from_prepared(
        prepared: PreparedCapacityCommit,
    ) -> Result<(Self, Arc<PreparationOwnership>), AuditAuthorityError> {
        let PreparedCapacityCommit {
            commit,
            resolution,
            binding,
            evidence,
            reservation,
        } = prepared;
        let bad = AuditAuthorityError::InvalidInput;
        if resolution.is_some() || commit.record.confirmed_deadline.is_some() {
            return Err(bad);
        }
        let evidence = evidence
            .filter(|e| e.profile() == ConfigCapacityProfile::BoundedV1)
            .ok_or(bad)?;
        let reservation = reservation.ok_or(bad)?;
        let payload = Self {
            fields: Arc::new(PayloadFields {
                commit,
                binding: binding.ok_or(bad)?,
            }),
        };
        payload.validate()?;
        Ok((
            payload,
            PreparationOwnership::new(reservation, Some(evidence)),
        ))
    }

    // record_owners charges the embedded commit and its allocated fields.
    pub(in crate::consensus) fn fixed_owner_bytes(&self) -> usize {
        std::mem::size_of::<PayloadFields>() - std::mem::size_of::<PreparedConfigCommit>()
            + 2 * std::mem::size_of::<usize>()
    }

    pub(in crate::consensus) fn commit(&self) -> &PreparedConfigCommit {
        &self.fields.commit
    }
    pub(in crate::consensus) fn binding(&self) -> &CapacityRecordBinding {
        &self.fields.binding
    }

    pub(in crate::consensus) fn validate(&self) -> Result<(), AuditAuthorityError> {
        // Admit bounded framing and scalar AAD before the general record
        // decoder can allocate from untrusted recovery metadata.
        self.binding()
            .validate(&self.commit().record)
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        self.commit()
            .validate()
            .map_err(|_| AuditAuthorityError::InvalidInput)?;
        if self.commit().record.confirmed_deadline.is_some() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        Ok(())
    }
}

fn invalid<E: de::Error>() -> E {
    E::custom("invalid bounded NETCONF Running payload")
}

fn schema_digest<'de, D: Deserializer<'de>>(deserializer: D) -> Result<SchemaDigest, D::Error> {
    // SchemaDigest's general decoder owns a String. The joint boundary caps
    // that temporary too, before asking the existing canonical parser to check it.
    Text::<64>::deserialize(deserializer)?
        .0
        .parse()
        .map_err(de::Error::custom)
}

fn source_input<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<TargetSourceV1>, D::Error> {
    #[derive(Deserialize)]
    #[serde(
        remote = "TargetSourceV1",
        rename_all = "kebab-case",
        deny_unknown_fields
    )]
    enum Source {
        Running {
            version: u64,
            #[serde(deserialize_with = "schema_digest")]
            schema: SchemaDigest,
            ciphertext_digest: [u8; 32],
        },
        Candidate {
            generation: crate::audit_authority::CandidateGeneration,
            #[serde(deserialize_with = "schema_digest")]
            schema: SchemaDigest,
            ciphertext_digest: [u8; 32],
        },
        Startup {
            revision: crate::audit_authority::StartupRevision,
            #[serde(deserialize_with = "schema_digest")]
            schema: SchemaDigest,
            ciphertext_digest: [u8; 32],
        },
        CandidateFallback {
            generation: crate::audit_authority::CandidateGeneration,
            running_version: u64,
            #[serde(deserialize_with = "schema_digest")]
            schema: SchemaDigest,
            ciphertext_digest: [u8; 32],
        },
    }
    #[derive(Deserialize)]
    struct Input(#[serde(with = "Source")] TargetSourceV1);
    Option::<Input>::deserialize(deserializer).map(|source| source.map(|input| input.0))
}

fn absent_resolution<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<TargetResolutionV1>, D::Error> {
    struct Absent;
    impl<'de> Visitor<'de> for Absent {
        type Value = Option<TargetResolutionV1>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("no confirmed resolution")
        }
        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: Deserializer<'de>>(self, _: D) -> Result<Self::Value, D::Error> {
            Err(invalid())
        }
    }
    deserializer.deserialize_option(Absent)
}

#[derive(Deserialize)]
#[serde(rename = "CommitRecord", deny_unknown_fields)]
struct RecordInput {
    tx_id: TxId,
    parent_tx_id: Option<TxId>,
    version: ConfigVersion,
    committed_at: Timestamp,
    principal: Text<CONFIG_PRINCIPAL_MAX_BYTES>,
    source: crate::CommitSource,
    #[serde(deserialize_with = "schema_digest")]
    schema_digest: SchemaDigest,
    plaintext_digest: Bytes<32>,
    encrypted_blob: Bytes<CONFIG_CAPACITY_V1_ENVELOPE_BYTES>,
    rollback_point: bool,
    confirmed_deadline: Option<Timestamp>,
}

impl From<RecordInput> for CommitRecord {
    fn from(value: RecordInput) -> Self {
        Self {
            tx_id: value.tx_id,
            parent_tx_id: value.parent_tx_id,
            version: value.version,
            committed_at: value.committed_at,
            principal: value.principal.0,
            source: value.source,
            schema_digest: value.schema_digest,
            plaintext_digest: value.plaintext_digest.0,
            encrypted_blob: value.encrypted_blob.0,
            rollback_point: value.rollback_point,
            confirmed_deadline: value.confirmed_deadline,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "AuditRecord", deny_unknown_fields)]
struct AuditInput {
    tx_id: TxId,
    sequence: u32,
    yang_path: Text<CONFIG_AUDIT_PATH_MAX_BYTES>,
    op_type: crate::AuditOpType,
    previous_value: Option<Text<12>>,
    new_value: Option<Text<12>>,
    redaction_applied: bool,
    previous_hash: [u8; 32],
    entry_hmac: [u8; 32],
}

impl From<AuditInput> for AuditRecord {
    fn from(value: AuditInput) -> Self {
        Self {
            tx_id: value.tx_id,
            sequence: value.sequence,
            yang_path: value.yang_path.0,
            op_type: value.op_type,
            previous_value: value.previous_value.map(|v| v.0),
            new_value: value.new_value.map(|v| v.0),
            redaction_applied: value.redaction_applied,
            previous_hash: value.previous_hash,
            entry_hmac: value.entry_hmac,
        }
    }
}

struct AuditInputList(Vec<AuditRecord>);

impl<'de> Deserialize<'de> for AuditInputList {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AuditVisitor;
        impl<'de> Visitor<'de> for AuditVisitor {
            type Value = AuditInputList;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded finalized Running audit")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Self::Value, A::Error> {
                // Every entry includes two fixed hashes. Keep the existing loose
                // item ceiling as well as the independently accumulated bytes.
                const ITEMS: usize = CONFIG_CAPACITY_V1_METADATA_BYTES / 64;
                let hint = input.size_hint();
                let extent = hint.unwrap_or(ITEMS);
                if extent > ITEMS {
                    return Err(invalid());
                }
                let mut entries = Vec::new();
                let mut bytes = 0usize;
                while let Some(entry) = input.next_element::<AuditInput>()? {
                    if entries.len() == extent {
                        return Err(invalid());
                    }
                    let entry = AuditRecord::from(entry);
                    let mut size = opc_consensus::AppendEntriesBatchAccumulator::new();
                    size.consider(&entry).map_err(|_| invalid::<A::Error>())?;
                    bytes = bytes
                        .checked_add(size.serialized_entry_bytes())
                        .filter(|n| *n <= CONFIG_CAPACITY_V1_METADATA_BYTES)
                        .ok_or_else(invalid::<A::Error>)?;
                    reserve_next::<_, A::Error>(&mut entries, extent, hint, 16)?;
                    entries.push(entry);
                }
                Ok(AuditInputList(entries))
            }
        }
        deserializer.deserialize_seq(AuditVisitor)
    }
}

#[derive(Deserialize)]
#[serde(rename = "PreparedConfigCommit", deny_unknown_fields)]
struct CommitInput {
    record: RecordInput,
    audit: AuditInputList,
}

#[derive(Deserialize)]
#[serde(rename = "BoundedRunningPayloadV1", deny_unknown_fields)]
struct PayloadInput {
    commit: CommitInput,
    binding: CapacityRecordBinding,
}

impl From<PayloadInput> for BoundedRunningPayload {
    fn from(value: PayloadInput) -> Self {
        Self {
            fields: Arc::new(PayloadFields {
                commit: PreparedConfigCommit {
                    record: value.commit.record.into(),
                    audit: value.commit.audit.0,
                },
                binding: value.binding,
            }),
        }
    }
}

// Ordinals 0..2 are kept but never accept/allocate their former payloads here.
// This joint seam is ordinary Running replacement only. Old profiles keep their
// original three variants and decoder. New tags and fields are closed.
#[derive(Deserialize)]
#[serde(
    rename = "TargetPayloadV1",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
enum PayloadInputTag {
    Target,
    Running,
    ProviderCopy,
    BoundedRunning(Box<PayloadInput>),
}

#[derive(Deserialize)]
#[serde(rename = "TargetEffectV1", deny_unknown_fields)]
struct EffectInput {
    format: u16,
    #[serde(with = "crate::audit_authority::target_identity")]
    authority: ConfigConsensusIdentity,
    profile_incarnation: [u8; 16],
    device_incarnation: [u8; 16],
    #[serde(with = "crate::audit_authority::target_caller")]
    caller: AuditCaller,
    request: AuditToken,
    action: TargetActionV1,
    destination: TargetExpectationV1,
    #[serde(deserialize_with = "source_input")]
    source: Option<TargetSourceV1>,
    lock: Option<TargetLockExpectationV1>,
    expires_at: i64,
    encrypted_payload: Option<PayloadInputTag>,
    #[serde(deserialize_with = "absent_resolution")]
    resolution: Option<TargetResolutionV1>,
}

/// The same strict typed input works for received postcard and retained JSON.
/// Its constructors mint no store, caller, session or reservation authority.
#[derive(Deserialize)]
#[serde(rename = "PreparedTargetMutation", deny_unknown_fields)]
pub(in crate::consensus) struct Received {
    #[serde(deserialize_with = "crate::audit_authority::ledger::deserialize_target_handle")]
    handle: AuditOperationHandle,
    effect: EffectInput,
}

impl Received {
    fn into_prepared(self) -> Result<PreparedTargetMutation, AuditAuthorityError> {
        let EffectInput {
            format,
            authority,
            profile_incarnation,
            device_incarnation,
            caller,
            request,
            action,
            destination,
            source,
            lock,
            expires_at,
            encrypted_payload,
            resolution,
        } = self.effect;
        let Some(PayloadInputTag::BoundedRunning(payload)) = encrypted_payload else {
            return Err(AuditAuthorityError::BindingMismatch);
        };
        let prepared = PreparedTargetMutation::new(
            self.handle,
            TargetEffectV1 {
                format,
                authority,
                profile_incarnation,
                device_incarnation,
                caller,
                request,
                action,
                destination,
                source,
                lock,
                expires_at,
                encrypted_payload: Some(TargetPayloadV1::BoundedRunning((*payload).into())),
                resolution,
            },
            None,
        );
        prepared
            .command()
            .effect
            .validate_for_capacity(&prepared.command().handle, ConfigCapacityProfile::BoundedV1)?;
        Ok(prepared)
    }
}

/// Selected writable-Running subset. This is a command fence, never proof
/// of an admitted session or Intent. The existing reducer authenticates both.
pub(in crate::consensus) fn allows_native(command: &super::TargetMutationCommand) -> bool {
    let effect = &command.effect;
    match u8::from(effect.action) {
        0 | 1 | 13 => {
            effect.encrypted_payload.is_none() && effect.source.is_none() && effect.lock.is_none()
        }
        2 | 3 => {
            effect.encrypted_payload.is_none()
                && effect.source.is_none()
                && effect.lock.as_ref().is_some_and(|lock| lock.datastore == 0)
        }
        16 => {
            command.bounded_running().is_some()
                && effect.resolution.is_none()
                && matches!(effect.source, None | Some(TargetSourceV1::Running { .. }))
                && effect.lock.as_ref().is_some_and(|lock| lock.datastore == 0)
        }
        _ => false,
    }
}

#[derive(Deserialize)]
#[serde(rename = "TargetEffectV1", deny_unknown_fields)]
struct NativeEffectInput {
    format: u16,
    #[serde(with = "crate::audit_authority::target_identity")]
    authority: ConfigConsensusIdentity,
    profile_incarnation: [u8; 16],
    device_incarnation: [u8; 16],
    #[serde(with = "crate::audit_authority::target_caller")]
    caller: AuditCaller,
    request: AuditToken,
    action: TargetActionV1,
    destination: TargetExpectationV1,
    #[serde(deserialize_with = "source_input")]
    source: Option<TargetSourceV1>,
    lock: Option<TargetLockExpectationV1>,
    expires_at: i64,
    encrypted_payload: Option<PayloadInputTag>,
    // This closed type owns no unbounded string or collection. The command
    // validator rejects all confirmed/rollback variants in this native family.
    resolution: Option<TargetResolutionV1>,
}

#[derive(Deserialize)]
#[serde(rename = "PreparedTargetMutation", deny_unknown_fields)]
struct NativeFields {
    #[serde(deserialize_with = "crate::audit_authority::ledger::deserialize_target_handle")]
    handle: AuditOperationHandle,
    effect: NativeEffectInput,
}

pub(in crate::consensus) struct NativeReceived(
    pub(in crate::consensus) super::TargetMutationCommand,
);

impl<'de> Deserialize<'de> for NativeReceived {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = NativeFields::deserialize(deserializer)?;
        let effect = value.effect;
        let encrypted_payload = match effect.encrypted_payload {
            None => None,
            Some(PayloadInputTag::BoundedRunning(payload)) => {
                Some(TargetPayloadV1::BoundedRunning((*payload).into()))
            }
            // Old tags do not deserialize any record fields in this input.
            Some(_) => return Err(invalid()),
        };
        let prepared = PreparedTargetMutation::new(
            value.handle,
            TargetEffectV1 {
                format: effect.format,
                authority: effect.authority,
                profile_incarnation: effect.profile_incarnation,
                device_incarnation: effect.device_incarnation,
                caller: effect.caller,
                request: effect.request,
                action: effect.action,
                destination: effect.destination,
                source: effect.source,
                lock: effect.lock,
                expires_at: effect.expires_at,
                encrypted_payload,
                resolution: effect.resolution,
            },
            None,
        );
        if !allows_native(prepared.command()) {
            return Err(invalid());
        }
        let capacity = if prepared.bounded_running().is_some() {
            ConfigCapacityProfile::BoundedV1
        } else {
            ConfigCapacityProfile::Legacy
        };
        prepared
            .command()
            .effect
            .validate_for_capacity(prepared.handle(), capacity)
            .map_err(|_| invalid::<D::Error>())?;
        Ok(Self(prepared.command))
    }
}

#[cfg(test)]
pub(in crate::consensus) fn recover(
    bytes: &[u8],
    reservation: ConfigPreparationReservation,
    pool: &ConfigPreparationPool,
    identity: ConfigConsensusIdentity,
    key: &AuditKey,
    caller: AuditCaller,
) -> Result<PreparedTargetMutation, AuditAuthorityError> {
    // Hold the destination's reservation before parsing strings or collections.
    if !pool.owns(&reservation) {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    hydrate(
        decode_unowned(bytes)?,
        reservation,
        pool,
        identity,
        key,
        caller,
    )
}

// Representation-only decoding for authenticated retained ledger validation.
// It reuses the same bounded field visitors and grants no local preparation.
pub(super) fn decode_unowned(bytes: &[u8]) -> Result<PreparedTargetMutation, AuditAuthorityError> {
    if bytes.len() > crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES {
        return Err(AuditAuthorityError::InvalidInput);
    }
    json_string_preflight(bytes)?;
    serde_json::from_slice::<Received>(bytes)
        .map_err(|_| AuditAuthorityError::InvalidInput)?
        .into_prepared()
}

// The caller holds this exact destination's reservation before owned decoding.
// Move the decoded command, preserving its record allocation and original ID;
// recovered size proof is neither fresh encryption evidence nor an Intent.
pub(in crate::consensus) fn hydrate(
    mut prepared: PreparedTargetMutation,
    reservation: ConfigPreparationReservation,
    pool: &ConfigPreparationPool,
    identity: ConfigConsensusIdentity,
    key: &AuditKey,
    caller: AuditCaller,
) -> Result<PreparedTargetMutation, AuditAuthorityError> {
    if !pool.owns(&reservation) || prepared.preparation.is_some() {
        return Err(AuditAuthorityError::BindingMismatch);
    }
    let evidence = prepared.verify_bounded_running(key, identity, caller)?;
    crate::consensus::store::preflight_joint_target_payload(&prepared)?;
    prepared.preparation = Some(PreparationOwnership::recovered(reservation, evidence));
    Ok(prepared)
}

#[cfg(test)]
pub(in crate::consensus) use tests::{observe_record_aad_decode, observe_record_envelope_decode};

#[cfg(test)]
#[path = "joint_target_payload_tests.rs"]
pub(in crate::consensus) mod tests;
