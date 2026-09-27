//! Allocation-boundary detectors for the closed capacity audit family.
//! These exercise the production wire/native-row decoders, not SQL apply or
//! an authenticated transport. Successful decoding grants no mutation authority.

use super::{
    decode_forward_mutation, ConfigPeerCompatibility, ForwardMutationRequest, ForwardedBudget,
};
use crate::audit_authority::continuity::{
    checkpoint::CheckpointBody, AuditCheckpoint, AuditKeyRing, AuditKeyTransition, AuditSigningKey,
};
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditLedgerLimits, AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey,
    ProjectedAuditEvent,
};
use crate::consensus::audit::AuditCommand;
use crate::consensus::audit_mutation::TargetAuditCommandV1;
use crate::consensus::config_capacity_decode;
use crate::consensus::types::{
    config_command_revision, config_wire_revision, decode_config_wire_for_profile,
    encode_config_wire_for_profile,
};
use crate::consensus::{ConfigConsensusCommand, ConfigMutationIntent, ConfigRaftTypeConfig};
use crate::retained::RetainedConfigMode;
use crate::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusRequestId, ManagementAuditEventRecord, ManagementAuditInstant,
    ManagementAuditOperationCode, ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode,
    ManagementAuditTransportCode,
};
use opc_consensus::engine::raft::AppendEntriesRequest;
use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId, Vote};
use opc_crypto::{ConfigCapacityProfile, CONFIG_CAPACITY_V1_ENVELOPE_BYTES};
use serde::de::{self, DeserializeSeed, EnumAccess, VariantAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::json;
use std::cell::Cell;

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x61; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x62; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn key() -> AuditKey {
    AuditKey::new([0x63; 32]).unwrap()
}

fn handle() -> AuditOperationHandle {
    let privacy = AuditPrivacyKey::new([0x64; 32]).unwrap();
    let event = ManagementAuditEventRecord::try_new(
        [0x65; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        "synthetic-tenant",
        "synthetic-principal",
        ManagementAuditTransportCode::NetconfSsh,
        ManagementAuditOperationCode::Exec,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/synthetic:configuration"],
        None::<&str>,
    )
    .unwrap();
    let event = ProjectedAuditEvent::project(&privacy, &event).unwrap();
    let binding =
        AuditOperationBinding::project(&privacy, &event, 0, b"synthetic-discard").unwrap();
    AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding,
            event,
            issued_at: 100,
            expires_at: 160,
            nonce: [0x66; 16],
            key_epoch: key().epoch(),
            mutation: None,
        },
        &key(),
    )
    .unwrap()
}

fn old_commands() -> [AuditCommand; 9] {
    let handle = handle();
    let projection = handle.body.event.projection;
    let limits = AuditLedgerLimits::new(12, 4).unwrap();
    let keys = AuditKeyRing::new(vec![
        AuditSigningKey::new(1, [0x67; 32]).unwrap(),
        AuditSigningKey::new(2, [0x68; 32]).unwrap(),
    ])
    .unwrap();
    let checkpoint = AuditCheckpoint::issue(
        &keys,
        CheckpointBody {
            version: 1,
            identity: identity(),
            sequence: 1,
            root_anchor: [0x69; 32],
            anchor: [0x6a; 32],
            epoch_at_sequence: 1,
            signing_epoch: 1,
            acknowledged_export: [0x6b; 32],
        },
    )
    .unwrap();
    [
        AuditCommand::Initialize { projection, limits },
        AuditCommand::Intent(handle.clone()),
        AuditCommand::Reject(handle.clone()),
        AuditCommand::Terminal(handle),
        AuditCommand::InitializeWithContinuity {
            projection,
            limits,
            initial_epoch: 1,
        },
        AuditCommand::Transition(
            AuditKeyTransition::prepare(&keys, identity(), 1, [0x6a; 32], 1, 2).unwrap(),
        ),
        AuditCommand::Checkpoint(checkpoint.clone()),
        AuditCommand::Prune {
            through: 1,
            checkpoint: checkpoint.clone(),
        },
        AuditCommand::AcknowledgeExport(checkpoint),
    ]
}

fn entry(command: AuditCommand, revision: u16) -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: LogId::new(
            CommittedLeaderId::new(1, ConfigConsensusNodeId::new(1).unwrap()),
            3,
        ),
        payload: EntryPayload::Normal(ConfigConsensusCommand {
            schema_version: revision,
            identity: identity(),
            request_id: ConfigConsensusRequestId::from_bytes([0x6c; 16]),
            logical_time: "2026-01-01T00:00:00Z".parse().unwrap(),
            intent: ConfigMutationIntent::ManagementAudit(Box::new(command)),
        }),
    }
}

fn append(entry: Entry<ConfigRaftTypeConfig>) -> AppendEntriesRequest<ConfigRaftTypeConfig> {
    AppendEntriesRequest {
        vote: Vote::new_committed(1, ConfigConsensusNodeId::new(1).unwrap()),
        prev_log_id: None,
        entries: vec![entry],
        leader_commit: None,
    }
}

fn forward(command: AuditCommand, mode: RetainedConfigMode) -> ForwardMutationRequest {
    ForwardMutationRequest {
        request_id: ConfigConsensusRequestId::from_bytes([0x6c; 16]),
        intent: ConfigMutationIntent::ManagementAudit(Box::new(command)),
        compatibility: ConfigPeerCompatibility {
            wire_version: config_wire_revision(mode),
            command_version: config_command_revision(mode),
            audit_key_epoch: key().epoch(),
            audit_key_fingerprint: key().fingerprint(),
        },
        budget: ForwardedBudget {
            remaining_nanos: 1_000_000_000,
        },
    }
}

#[test]
fn three_mode_capacity_audit_gate_preserves_all_original_audit_variants() {
    let mode = RetainedConfigMode::BoundedV1;
    for (tag, command) in old_commands().into_iter().enumerate() {
        assert_eq!(
            opc_consensus::encode_bounded(&command).unwrap()[0],
            tag as u8
        );
        let source = entry(command.clone(), 8);
        let request = append(source.clone());
        let bytes = encode_config_wire_for_profile(mode, &request).unwrap();
        let decoded =
            config_capacity_decode::engine::append(ConfigCapacityProfile::BoundedV1, &bytes)
                .expect("original audit append variant");
        assert!(
            encode_config_wire_for_profile(mode, &decoded).unwrap() == bytes,
            "THREE_MODE_AUDIT_APPEND_BYTES"
        );
        let forwarded = forward(command, mode);
        let bytes = encode_config_wire_for_profile(mode, &forwarded).unwrap();
        assert!(
            decode_forward_mutation(mode, &bytes).unwrap() == forwarded,
            "THREE_MODE_AUDIT_FORWARD_BYTES"
        );
        for malformed in [&bytes[..bytes.len() / 2], &bytes[..bytes.len() - 1]] {
            assert!(decode_forward_mutation(mode, malformed).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_forward_mutation(mode, &trailing).is_err());

        let canonical = serde_json::to_vec(&source).unwrap();
        let mut forms = vec![
            canonical.clone(),
            serde_json::to_vec_pretty(&source).unwrap(),
            serde_json::to_vec(&serde_json::to_value(&source).unwrap()).unwrap(),
        ];
        if tag == 0 {
            // Preserve previously accepted unknown struct fields and escaped
            // variant names. Closed variant selection must not tighten these.
            let text = std::str::from_utf8(&canonical).unwrap();
            forms.push(
                text.replace("\"initialize\":{", "\"initialize\":{\"extra\":0,")
                    .into_bytes(),
            );
            forms.push(
                text.replace("\"initialize\":", "\"\\u0069nitialize\":")
                    .into_bytes(),
            );
        }
        for bytes in forms {
            let original: Entry<ConfigRaftTypeConfig> = serde_json::from_slice(&bytes).unwrap();
            assert!(original == source, "original codec fixture");
            let decoded = config_capacity_decode::engine::native_entry(
                ConfigCapacityProfile::BoundedV1,
                &bytes,
            )
            .expect("original audit native-row form");
            assert!(decoded == original, "THREE_MODE_AUDIT_NATIVE_COMPATIBILITY");
            assert!(serde_json::to_vec(&decoded).unwrap() == canonical);
        }
    }
}

fn target_command(payload: Option<Vec<u8>>) -> AuditCommand {
    let handle = handle();
    let event = handle.body.event.clone();
    let encrypted_payload = payload.map(|bytes| {
        json!({"target": {
            "schema": opc_types::SchemaDigest::from_bytes([0x71; 32]),
            "plaintext_digest": vec![0x72u8; 32],
            "encrypted_blob": bytes
        }})
    });
    let mut command: AuditCommand = serde_json::from_value(json!({"netconf-target": {"apply": {
        "handle": handle,
        "effect": {
            "format": 1,
            "authority": identity(),
            "profile_incarnation": vec![0x73u8; 16],
            "device_incarnation": vec![0x74u8; 16],
            "caller": event.caller,
            "request": event.request,
            "action": 5,
            "destination": {"candidate": {"generation": {"authority": identity(), "value": 0}}},
            "source": null,
            "lock": {"datastore": 1, "incarnation": 1, "session": vec![0x75u8; 16], "requester": vec![0x75u8; 16]},
            "expires_at": 160,
            "encrypted_payload": encrypted_payload,
            "resolution": null
        }
    }}})).unwrap();
    let AuditCommand::NetconfTarget(target) = &mut command else {
        unreachable!("target fixture");
    };
    let TargetAuditCommandV1::Apply(prepared) = target.as_mut() else {
        unreachable!("target apply fixture");
    };
    let mut body = prepared.handle.body.clone();
    body.mutation = Some(prepared.effect.digest(&key()).unwrap());
    prepared.handle = AuditOperationHandle::issue(body, &key()).unwrap();
    if prepared.effect.encrypted_payload.is_none() {
        prepared
            .verify_effect(&key())
            .expect("valid signed target control");
    }
    // The deliberately oversized-body case is only syntactically decodable:
    // a capacity receiver must reject the family before authenticating it.
    command
}

fn target_cases() -> [AuditCommand; 2] {
    // This positive target9 control retains its real signature and exact wire.
    // It proves the rejection below is selected by the capacity decode mode.
    let target = RetainedConfigMode::NetconfTargetsV1;
    let control = target_command(None);
    let request = append(entry(control.clone(), 9));
    let bytes = encode_config_wire_for_profile(target, &request).unwrap();
    let decoded: AppendEntriesRequest<ConfigRaftTypeConfig> =
        decode_config_wire_for_profile(target, &bytes).unwrap();
    assert!(encode_config_wire_for_profile(target, &decoded).unwrap() == bytes);
    let request = forward(control.clone(), target);
    let bytes = encode_config_wire_for_profile(target, &request).unwrap();
    assert!(decode_forward_mutation(target, &bytes).unwrap() == request);
    [
        control,
        target_command(Some(vec![0x76; CONFIG_CAPACITY_V1_ENVELOPE_BYTES + 1])),
    ]
}

#[test]
fn three_mode_capacity_audit_gate_rejects_target_append_payload() {
    let bounded = RetainedConfigMode::BoundedV1;
    for command in target_cases() {
        for revision in [8, 9] {
            let request = append(entry(command.clone(), revision));
            let bytes = encode_config_wire_for_profile(bounded, &request).unwrap();
            // The shared decoder accepts the complete body. The capacity DTO
            // must refuse it before semantic revision or effect verification.
            let decoded: AppendEntriesRequest<ConfigRaftTypeConfig> =
                decode_config_wire_for_profile(bounded, &bytes).unwrap();
            assert!(encode_config_wire_for_profile(bounded, &decoded).unwrap() == bytes);
            assert!(
                config_capacity_decode::engine::append(ConfigCapacityProfile::BoundedV1, &bytes)
                    .is_err(),
                "THREE_MODE_AUDIT_TARGET_APPEND_GATE"
            );
        }
    }
}

#[test]
fn three_mode_capacity_audit_gate_rejects_target_forward_payload() {
    let bounded = RetainedConfigMode::BoundedV1;
    for command in target_cases() {
        let request = forward(command, bounded);
        let bytes = encode_config_wire_for_profile(bounded, &request).unwrap();
        let decoded: ForwardMutationRequest =
            decode_config_wire_for_profile(bounded, &bytes).unwrap();
        assert!(decoded == request, "complete forwarding fixture");
        assert!(
            decode_forward_mutation(bounded, &bytes).is_err(),
            "THREE_MODE_AUDIT_TARGET_FORWARD_GATE"
        );
    }
}

#[test]
fn three_mode_capacity_audit_gate_rejects_target_native_row_payload() {
    for command in target_cases() {
        for revision in [8, 9] {
            let source = entry(command.clone(), revision);
            for bytes in [
                serde_json::to_vec(&source).unwrap(),
                serde_json::to_vec(&serde_json::to_value(&source).unwrap()).unwrap(),
            ] {
                assert!(
                    bytes.len() <= crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES
                );
                let original: Entry<ConfigRaftTypeConfig> = serde_json::from_slice(&bytes).unwrap();
                assert!(original == source, "complete native-row fixture");
                assert!(
                    config_capacity_decode::engine::native_entry(
                        ConfigCapacityProfile::BoundedV1,
                        &bytes,
                    )
                    .is_err(),
                    "THREE_MODE_AUDIT_TARGET_NATIVE_GATE"
                );
            }
        }
    }
}

// This probe drives the same derived Intent deserializer used by every path
// above. Its nested body cannot allocate: entering it records the ordering
// violation. The unchanged original decoder reaches this body; the closed DTO
// must reject the JSON name and binary discriminant before requesting it.
#[derive(Clone, Copy)]
enum Layer {
    Intent,
    Audit,
}

struct BodyProbe<'a> {
    layer: Layer,
    index: bool,
    entered: &'a Cell<bool>,
}

fn probe_error() -> de::value::Error {
    de::Error::custom("audit target body must not be deserialized")
}

impl<'de> Deserializer<'de> for BodyProbe<'_> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        Err(probe_error())
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_enum(self)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map struct
        identifier ignored_any
    }
}

impl<'de> EnumAccess<'de> for BodyProbe<'_> {
    type Error = de::value::Error;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(
        self,
        seed: V,
    ) -> Result<(V::Value, Self::Variant), Self::Error> {
        let value = if self.index {
            let tag = match self.layer {
                Layer::Intent => 6,
                Layer::Audit => 9,
            };
            seed.deserialize(de::value::U32Deserializer::<Self::Error>::new(tag))?
        } else {
            let name = match self.layer {
                Layer::Intent => "ManagementAudit",
                Layer::Audit => "netconf-target",
            };
            seed.deserialize(de::value::BorrowedStrDeserializer::<Self::Error>::new(name))?
        };
        Ok((value, self))
    }
}

impl<'de> VariantAccess<'de> for BodyProbe<'_> {
    type Error = de::value::Error;

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(
        self,
        seed: T,
    ) -> Result<T::Value, Self::Error> {
        match self.layer {
            Layer::Intent => seed.deserialize(Self {
                layer: Layer::Audit,
                ..self
            }),
            Layer::Audit => {
                self.entered.set(true);
                Err(probe_error())
            }
        }
    }

    fn unit_variant(self) -> Result<(), Self::Error> {
        Err(probe_error())
    }

    fn tuple_variant<V: Visitor<'de>>(self, _: usize, _: V) -> Result<V::Value, Self::Error> {
        Err(probe_error())
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Self::Error> {
        Err(probe_error())
    }
}

#[test]
fn three_mode_capacity_audit_gate_rejects_discriminant_before_reading_body() {
    for index in [false, true] {
        let entered = Cell::new(false);
        assert!(config_capacity_decode::Intent::deserialize(BodyProbe {
            layer: Layer::Intent,
            index,
            entered: &entered,
        })
        .is_err());
        assert!(!entered.get(), "THREE_MODE_AUDIT_BODY_BEFORE_ALLOCATION");
    }
}
