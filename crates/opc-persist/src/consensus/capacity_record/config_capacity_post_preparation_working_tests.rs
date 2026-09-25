//! Necessary SDK-owned heap evidence after successful preparation.
//! These component controls exercise the real routing clone and recovery encoder.
//! No ledger write, consensus proposal, engine apply or larger-store admission.

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

const OPERATION_BYTES: usize = 33_554_432;
const HEADROOM_BYTES: usize = 16_384;
const LOGICAL_BYTES: usize = 262_144;
const REPLAY_BYTES: usize = 64;

fn prepared(expanded: bool) -> Option<(PreparedConfigCommit, CapacityRecordBinding)> {
    let attested = fixture(LOGICAL_BYTES, REPLAY_BYTES, true);
    let binding = CapacityRecordBinding::issue(&attested, scope(), &key(), PROFILE)
        .expect("genuine size and record proof");
    let (mut record, audit, resolution) = attested.into_parts();
    assert!(resolution.is_none());
    assert_eq!(audit.capacity(), 0);
    {
        let envelope = opc_crypto::CryptoEnvelopeRef::decode(&record.encrypted_blob)
            .expect("genuine envelope framing");
        let (aad, bound_key) =
            opc_key::decode_bound_aad(envelope.aad).expect("authenticated fixture AAD");
        let handle = opc_key::KeyHandle::new(
            opc_key::KeyId::new("capacity-record-proof").expect("synthetic key ID"),
            opc_key::KeyPurpose::Config,
            TenantId::from_static("test"),
            opc_key::Zeroizing::new([0xA7; 32]),
        );
        assert!(bound_key == *handle.key_id());
        let recovered =
            opc_crypto::decrypt_envelope_with_handle(&handle, &aad, &record.encrypted_blob)
                .expect("genuine authenticated readback");
        assert!(
            recovered.as_slice() == plaintext(LOGICAL_BYTES, REPLAY_BYTES),
            "exact logical and replay readback"
        );
    }
    if expanded {
        let other = std::mem::size_of::<PreparedConfigCommit>()
            + record.principal.capacity()
            + record.plaintext_digest.capacity();
        let target = OPERATION_BYTES - HEADROOM_BYTES - other;
        let original = record.encrypted_blob.clone();
        record
            .encrypted_blob
            .try_reserve_exact(target - record.encrypted_blob.len())
            .expect("capacity-only fixture allocation");
        assert!(
            record.encrypted_blob == original,
            "unchanged authenticated bytes"
        );
        drop(original);
        assert_eq!(
            record.encrypted_blob.capacity() + other,
            OPERATION_BYTES - HEADROOM_BYTES
        );
    }
    binding
        .verify(&record, scope(), &key(), PROFILE)
        .expect("capacity does not change the original proof");
    match PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE) {
        Ok(prepared) => {
            prepared
                .validate()
                .expect("prepared genuine record structure");
            Some((prepared, binding))
        }
        Err(error) => {
            assert!(expanded, "compact genuine preparation must succeed");
            assert!(
                matches!(error.kind(), crate::PersistErrorKind::ConstraintViolation(message)
                if message == "config preparation allocation exceeds working limit"),
                "valid expanded input may only be rejected by capacity admission"
            );
            None
        }
    }
}

fn heap_bytes(commit: &PreparedConfigCommit) -> usize {
    assert!(commit.audit.is_empty());
    assert_eq!(commit.audit.capacity(), 0);
    commit.record.encrypted_blob.capacity()
        + commit.record.plaintext_digest.capacity()
        + commit.record.principal.capacity()
}

fn audited_fixture(effect: AuditedConfigEffect) -> PreparedAuditedMutation {
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

fn command(intent: ConfigMutationIntent, logical_time: Timestamp) -> ConfigConsensusCommand {
    ConfigConsensusCommand {
        schema_version: 8,
        identity: scope(),
        request_id: ConfigConsensusRequestId::from_bytes([0xC1; 16]),
        logical_time,
        intent,
    }
}

fn command_bytes(command: &ConfigConsensusCommand) -> usize {
    let mut size = opc_consensus::AppendEntriesBatchAccumulator::new();
    size.consider(command)
        .expect("actual borrowed complete command size");
    let bytes = size.serialized_entry_bytes();
    assert!(
        bytes <= opc_consensus::DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES,
        "the unchanged complete-command ceiling cannot mask this component detector"
    );
    bytes
}

fn routing_case(expanded: bool) {
    let Some((commit, binding)) = prepared(expanded) else {
        // Refusal before the SDK routing copy is valid capacity admission.
        return;
    };
    let logical_time = commit.record.committed_at;
    let original = ConfigMutationIntent::BoundedAppend {
        commit: Box::new(commit),
        binding,
        resolution: None,
    };
    original
        .validate_capacity(scope(), &key(), PROFILE)
        .expect("genuine original intent preserves its scoped proof");
    // submit_owned_request_inner retains this original intent and uses this
    // exact Clone implementation in each local/forwarded request. This is a
    // necessary component control, not a route or transport execution test.
    let copied = original.clone();
    copied
        .validate_capacity(scope(), &key(), PROFILE)
        .expect("actual routing copy preserves its scoped proof");
    let command = command(copied, logical_time);
    let encoded_bytes = command_bytes(&command);
    let ConfigMutationIntent::BoundedAppend { commit: source, .. } = &original else {
        panic!("fixture original append intent");
    };
    let ConfigMutationIntent::BoundedAppend { commit: copied, .. } = &command.intent else {
        panic!("actual copied append intent");
    };
    assert!(
        source.record.encrypted_blob == copied.record.encrypted_blob,
        "the real conversion preserves exact ciphertext"
    );
    assert_ne!(
        source.record.encrypted_blob.as_ptr(),
        copied.record.encrypted_blob.as_ptr(),
        "these nonempty input buffers are distinct allocations"
    );
    let source_bytes = heap_bytes(source);
    let copied_bytes = heap_bytes(copied);
    let live_lower_bound = source_bytes
        .checked_add(copied_bytes)
        .expect("finite simultaneous routing copy lower bound");
    eprintln!(
        "CONFIG_CAPACITY_POST_PREPARATION path=routing expanded={expanded} source_bytes={source_bytes} copied_bytes={copied_bytes} command_bytes={encoded_bytes} live_lower_bound={live_lower_bound} proposed_operation_bound={OPERATION_BYTES}",
    );
    assert!(live_lower_bound <= OPERATION_BYTES,
        "CONFIG_CAPACITY_POST_PREPARATION: original prepared intent and actual SDK routing copy exceed the entire proposed operation bound");
    std::hint::black_box((&original, &command));
}

fn recovery_case(expanded: bool) {
    let Some((commit, binding)) = prepared(expanded) else {
        // Refusal before owned recovery encoding is valid capacity admission.
        return;
    };
    let logical_time = commit.record.committed_at;
    let recovered = binding
        .recover(&commit.record, scope(), &key(), PROFILE)
        .expect("genuine record capacity evidence");
    let pool = opc_crypto::ConfigPreparationPool::bounded_v1();
    let owner = PreparationOwnership::recovered(
        pool.try_reserve().expect("one local preparation slot"),
        recovered,
    );
    assert!(owner.belongs_to(&pool, PROFILE, true));
    let mut prepared = audited_fixture(AuditedConfigEffect::BoundedAppend {
        commit: Box::new(commit),
        binding,
        resolution: None,
    });
    prepared.attach_preparation(owner);
    prepared
        .verify_effect(&key())
        .expect("genuine authenticated effect");
    let command = command(
        ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
        logical_time,
    );
    let encoded_bytes = command_bytes(&command);
    let recovery = prepared
        .encode()
        .expect("actual reserved SDK recovery encoder");
    assert!(recovery.len() <= crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES);
    let AuditedConfigEffect::BoundedAppend { commit: source, .. } = &prepared.command().effect
    else {
        panic!("fixture audited append effect");
    };
    let source_bytes = heap_bytes(source);
    let recovery_bytes = recovery.capacity();
    let live_lower_bound = source_bytes
        .checked_add(recovery_bytes)
        .expect("finite simultaneous recovery encoding lower bound");
    // encode owns this Vec while serializing and moves it out unchanged. Its
    // final capacity and the immutable borrowed source therefore coexist before
    // the output becomes caller-owned. We do not count the shared command twice.
    eprintln!(
        "CONFIG_CAPACITY_POST_PREPARATION path=recovery expanded={expanded} source_bytes={source_bytes} recovery_bytes={recovery_bytes} command_bytes={encoded_bytes} live_lower_bound={live_lower_bound} proposed_operation_bound={OPERATION_BYTES}",
    );
    assert!(live_lower_bound <= OPERATION_BYTES,
        "CONFIG_CAPACITY_POST_PREPARATION: original prepared record and actual SDK recovery output exceed the entire proposed operation bound");
    std::hint::black_box((&prepared, &command, &recovery, &pool));
}

#[test]
fn config_capacity_957_preparation_reserves_for_actual_routing_copy() {
    routing_case(false);
    routing_case(true);
}

#[test]
fn config_capacity_957_preparation_reserves_for_actual_recovery_output() {
    recovery_case(false);
    recovery_case(true);
}

#[path = "config_capacity_recovery_headroom_tests.rs"]
mod recovery_headroom_tests;
