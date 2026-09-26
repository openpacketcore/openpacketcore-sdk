//! Command and admission controls. These do not qualify retained storage,
//! transport, whole-operation allocation or opening the larger profile.

use super::*;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::{AuditedConfigEffect, PreparedAuditedMutation};
use crate::consensus::preparation::PreparationOwnership;
use crate::consensus::types::{
    ConfigConsensusCommand, ConfigConsensusRequestId, ConfigMutationIntent, PreparedConfigCommit,
};
use crate::ConfirmedCommitResolution;
use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId};
use serde::ser::SerializeStructVariant;
use serde::Serializer;

fn parts() -> (PreparedConfigCommit, CapacityRecordBinding) {
    let attested = fixture(32, 64, true);
    let binding = CapacityRecordBinding::issue(&attested, scope(), &key(), PROFILE)
        .expect("paired exact record proof");
    let (record, audit, _) = attested.into_parts();
    let prepared = PreparedConfigCommit::prepare(record, audit, &key()).expect("prepared record");
    (prepared, binding)
}

fn command(intent: ConfigMutationIntent) -> ConfigConsensusCommand {
    ConfigConsensusCommand {
        schema_version: 8,
        identity: scope(),
        request_id: ConfigConsensusRequestId::from_bytes([0xB1; 16]),
        logical_time: parts().0.record.committed_at,
        intent,
    }
}

fn audited(effect: AuditedConfigEffect) -> PreparedAuditedMutation {
    let privacy = AuditPrivacyKey::new([0xB2; 32]).expect("synthetic privacy key");
    let event = crate::ManagementAuditEventRecord::try_new(
        [0xB3; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .expect("synthetic event time"),
        "test",
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:config"],
        Some("synthetic-capacity-command"),
    )
    .expect("synthetic intent event");
    let event = ProjectedAuditEvent::project(&privacy, &event).expect("project event");
    let digest = effect.digest(&key()).expect("exact effect MAC");
    let binding =
        AuditOperationBinding::project(&privacy, &event, 6, &digest).expect("exact binding");
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: scope(),
            binding,
            event,
            issued_at: 100,
            expires_at: 160,
            nonce: [0xB4; 16],
            key_epoch: key().epoch(),
            mutation: Some(digest),
        },
        &key(),
    )
    .expect("synthetic operation handle, not an admitted receipt");
    PreparedAuditedMutation::new(handle, effect, None)
}

fn bounded_command(
    audit: bool,
    resolution: Option<ConfirmedCommitResolution>,
) -> ConfigConsensusCommand {
    let (commit, binding) = parts();
    command(if audit {
        ConfigMutationIntent::AuditedMutation(
            audited(AuditedConfigEffect::BoundedAppend {
                commit: Box::new(commit),
                binding,
                resolution,
            })
            .command()
            .clone(),
        )
    } else {
        ConfigMutationIntent::prepared_append(commit, resolution, Some(binding))
    })
}

#[test]
fn config_capacity_957_bound_commands_require_revision_eight_and_admitted_profile() {
    for audit in [false, true] {
        let mut value = bounded_command(audit, None);
        assert_eq!(value.intent.minimum_command_version(), 8);
        value
            .validate_for_profile(scope(), &key(), PROFILE)
            .expect("exact scoped proof");
        assert!(value
            .validate_for_profile(scope(), &key(), ConfigCapacityProfile::Legacy)
            .is_err());
        for revision in 1..=7 {
            value.schema_version = revision;
            assert!(
                value.validate(scope()).is_err(),
                "new effect cannot masquerade as old revision"
            );
        }
        value.schema_version = 8;
        let wire = opc_consensus::encode_bounded(&value).expect("actual encoded small command");
        let decoded: ConfigConsensusCommand = opc_consensus::decode_bounded(&wire).expect("decode");
        assert!(decoded == value, "exact command postcard roundtrip");
        decoded
            .validate_for_profile(scope(), &key(), PROFILE)
            .expect("keyed decoded validation");
        let json = serde_json::to_vec(&value).expect("durable command JSON");
        assert!(
            serde_json::from_slice::<ConfigConsensusCommand>(&json).expect("decode JSON") == value,
            "exact command JSON roundtrip"
        );
    }
    let (commit, _) = parts();
    let unbound = command(ConfigMutationIntent::prepared_append(
        commit.clone(),
        None,
        None,
    ));
    assert!(unbound
        .validate_for_profile(scope(), &key(), PROFILE)
        .is_err());
    let unbound = command(ConfigMutationIntent::AuditedMutation(
        audited(AuditedConfigEffect::Append {
            commit: Box::new(commit),
            resolution: None,
        })
        .command()
        .clone(),
    ));
    assert!(unbound
        .validate_for_profile(scope(), &key(), PROFILE)
        .is_err());
}

#[test]
fn config_capacity_957_bound_commands_authenticate_proof_even_with_a_valid_operation_handle() {
    for audit in [false, true] {
        for change_digest in [false, true] {
            let (mut commit, mut binding) = parts();
            if change_digest {
                commit.record.plaintext_digest[0] ^= 1;
            } else {
                binding.tag[0] ^= 1;
            }
            let value = if audit {
                let prepared = audited(AuditedConfigEffect::BoundedAppend {
                    commit: Box::new(commit),
                    binding,
                    resolution: None,
                });
                prepared
                    .command()
                    .verify_effect(&key())
                    .expect("separate operation MAC is valid");
                command(ConfigMutationIntent::AuditedMutation(
                    prepared.command().clone(),
                ))
            } else {
                command(ConfigMutationIntent::prepared_append(
                    commit,
                    None,
                    Some(binding),
                ))
            };
            value
                .validate(scope())
                .expect("structurally valid is not authenticated");
            assert!(value
                .validate_for_profile(scope(), &key(), PROFILE)
                .is_err());
        }
        let value = bounded_command(audit, None);
        assert!(value
            .validate_for_profile(
                scope(),
                &AuditKey::new_with_epoch([0xC1; 32], 4).expect("different synthetic key"),
                PROFILE
            )
            .is_err());
        let mut other_authority = value;
        other_authority.identity = identity(0xC2, 0xA2, 3);
        assert!(other_authority
            .validate_for_profile(other_authority.identity, &key(), PROFILE)
            .is_err());
    }
}

#[test]
fn config_capacity_957_bound_confirmed_successors_preserve_exact_parent_rules() {
    let parent = parts()
        .0
        .record
        .parent_tx_id
        .expect("synthetic pending parent");
    for audit in [false, true] {
        for resolution in [
            ConfirmedCommitResolution::Confirm {
                pending_tx_id: parent,
            },
            ConfirmedCommitResolution::Rollback {
                pending_tx_id: parent,
            },
        ] {
            bounded_command(audit, Some(resolution))
                .validate_for_profile(scope(), &key(), PROFILE)
                .expect("same exact parent and immutable proof");
        }
        let mismatch = ConfirmedCommitResolution::Confirm {
            pending_tx_id: parts().0.record.tx_id,
        };
        assert!(bounded_command(audit, Some(mismatch))
            .validate(scope())
            .is_err());
    }
}

// Freeze the original ordinary enum encodings independently of the new variants.
struct LegacyAppend<'a>(&'a PreparedConfigCommit, Option<ConfirmedCommitResolution>);

impl Serialize for LegacyAppend<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.1 {
            None => serializer.serialize_newtype_variant(
                "ConfigMutationIntent",
                0,
                "AppendCommit",
                self.0,
            ),
            Some(resolution) => {
                let mut value = serializer.serialize_struct_variant(
                    "ConfigMutationIntent",
                    3,
                    "ResolveConfirmedAndAppend",
                    2,
                )?;
                value.serialize_field("commit", self.0)?;
                value.serialize_field("resolution", &resolution)?;
                value.end()
            }
        }
    }
}

#[test]
fn config_capacity_957_bound_variant_preserves_legacy_append_bytes_and_semantic_digest() {
    let (commit, _) = parts();
    for resolution in [
        None,
        Some(ConfirmedCommitResolution::Confirm {
            pending_tx_id: commit.record.parent_tx_id.expect("parent"),
        }),
    ] {
        let old = LegacyAppend(&commit, resolution);
        let intent = ConfigMutationIntent::prepared_append(commit.clone(), resolution, None);
        assert_eq!(
            serde_json::to_vec(&intent).expect("current JSON"),
            serde_json::to_vec(&old).expect("legacy JSON")
        );
        assert_eq!(
            opc_consensus::encode_bounded(&intent).expect("current postcard"),
            opc_consensus::encode_bounded(&old).expect("legacy postcard")
        );
        let semantic_revision = if resolution.is_some() { 2_u16 } else { 1_u16 };
        let mut digest = Sha256::new();
        digest.update(b"openpacketcore/config-consensus/outcome/v1\0");
        digest.update(
            serde_json::to_vec(&(semantic_revision, scope(), &old)).expect("original transcript"),
        );
        let expected: [u8; 32] = digest.finalize().into();
        let mut current = command(intent);
        for revision in semantic_revision..=7 {
            current.schema_version = revision;
            current
                .validate_for_profile(scope(), &key(), ConfigCapacityProfile::Legacy)
                .expect("legacy command retained");
            assert_eq!(
                current.payload_digest().expect("same semantic digest"),
                expected
            );
        }
    }
    let (commit, binding) = parts();
    let bounded = ConfigMutationIntent::prepared_append(commit.clone(), None, Some(binding));
    assert_eq!(
        opc_consensus::encode_bounded(&bounded).expect("bounded variant")[0],
        8
    );
    let bounded = AuditedConfigEffect::BoundedAppend {
        commit: Box::new(commit),
        binding,
        resolution: None,
    };
    assert_eq!(
        opc_consensus::encode_bounded(&bounded).expect("bounded effect")[0],
        3
    );
}

#[test]
fn config_capacity_957_recovered_proof_ownership_is_local_and_does_not_authorize_audit() {
    let (commit, binding) = parts();
    let pool = opc_crypto::ConfigPreparationPool::bounded_v1();
    let foreign = opc_crypto::ConfigPreparationPool::bounded_v1();
    let evidence = binding
        .recover(&commit.record, scope(), &key(), PROFILE)
        .expect("verified exact proof");
    let owner =
        PreparationOwnership::recovered(pool.try_reserve().expect("local reservation"), evidence);
    assert!(owner.belongs_to(&pool, PROFILE, true));
    assert!(!owner.belongs_to(&foreign, PROFILE, true));
    assert!(!owner.belongs_to(&pool, ConfigCapacityProfile::Legacy, true));
    let prepared = audited(AuditedConfigEffect::BoundedAppend {
        commit: Box::new(commit),
        binding,
        resolution: None,
    });
    // Generic deserialization cannot reconstruct process-local ownership.
    let bytes = prepared.encode().expect("caller-owned recovery bytes");
    let decoded = PreparedAuditedMutation::decode(&bytes).expect("decode without reservation");
    assert!(decoded.begin_submission(&pool, PROFILE).is_err());
    let mut recovered = decoded;
    recovered.attach_preparation(owner.clone());
    assert!(recovered.begin_submission(&foreign, PROFILE).is_err());
    let submitting = recovered
        .begin_submission(&pool, PROFILE)
        .expect("local ownership only");
    assert!(recovered.begin_submission(&pool, PROFILE).is_err());
    let remaining: Vec<_> = (0..7)
        .map(|_| pool.try_reserve().expect("remaining slots"))
        .collect();
    assert!(pool.try_reserve().is_err());
    drop(owner);
    drop(recovered);
    assert!(
        pool.try_reserve().is_err(),
        "accepted submission retains its slot"
    );
    drop(submitting);
    assert!(pool.try_reserve().is_ok());
    drop(remaining);
    // There is no Intent receipt or ledger mutation anywhere in this fixture.
}

#[test]
fn config_capacity_957_replication_admission_uses_the_expected_authority() {
    let node = crate::consensus::ConfigConsensusNodeId::new(1).expect("synthetic voter");
    let mut entries = vec![Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, node), 1),
        payload: EntryPayload::Normal(bounded_command(false, None)),
    }];
    let admit = crate::consensus::sqlite::validate_entry_capacities;
    admit(&entries, scope(), &key(), PROFILE).expect("admitted private proof boundary");
    assert!(admit(&entries, scope(), &key(), ConfigCapacityProfile::Legacy).is_err());
    if let EntryPayload::Normal(value) = &mut entries[0].payload {
        if let ConfigMutationIntent::BoundedAppend { binding, .. } = &mut value.intent {
            binding.tag[0] ^= 1;
        }
    }
    assert!(admit(&entries, scope(), &key(), PROFILE).is_err());
    // This is the shared pre-handoff/pre-WAL predicate, not a WAL or RPC run.
}
