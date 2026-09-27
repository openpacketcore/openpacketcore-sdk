//! Inclusive admission of actual simultaneous command/output capacities.

use super::super::config_capacity_command_buffers::{CommandBuffers, OPERATION_BYTES};
use super::*;
use crate::consensus::audit_mutation::AuditedConfigEffect;

fn audited_command() -> ConfigConsensusCommand {
    let mut command = command(1_572_864);
    let ConfigMutationIntent::BoundedAppend {
        commit,
        binding,
        resolution,
    } = command.intent
    else {
        panic!("genuine bounded fixture");
    };
    let prepared = super::decoding::audited(AuditedConfigEffect::BoundedAppend {
        commit,
        binding,
        resolution,
    });
    prepared.verify_effect(&key()).unwrap();
    command.intent = ConfigMutationIntent::AuditedMutation(prepared.command().clone());
    command
}

#[test]
fn capacity_command_counts_independent_native_and_recovery_outputs() {
    let command = audited_command();
    let sizes = preflight(&probe(&command), PROFILE).unwrap();
    let ConfigMutationIntent::AuditedMutation(prepared) = &command.intent else {
        panic!("audited fixture");
    };
    let recovery = serde_json::to_vec(prepared).unwrap();
    assert_eq!(sizes.recovery_json, recovery.len());
    assert!(sizes.recovery_json > 4 * 1024 * 1024);
    let node = ConsensusNodeId::new(CONSENSUS_NODE_ID_MAX).unwrap();
    let entry = Entry::<ConfigRaftTypeConfig> {
        log_id: LogId::new(CommittedLeaderId::new(u64::MAX, node), u64::MAX),
        payload: EntryPayload::Normal(command.clone()),
    };
    let native = serde_json::to_vec(&entry).unwrap();
    assert_eq!(sizes.durable_json, native.len());
    assert!(native.len() > recovery.len());
    let with_both = CommandBuffers::for_command(&command.intent, &sizes)
        .unwrap()
        .total()
        .unwrap();
    let without_recovery = EncodingSizes {
        recovery_json: 0,
        ..sizes
    };
    let with_one = CommandBuffers::for_command(&command.intent, &without_recovery)
        .unwrap()
        .total()
        .unwrap();
    assert_eq!(with_both - with_one, recovery.len());
    assert!(with_both <= OPERATION_BYTES);
    std::hint::black_box((&entry, &native, &recovery));
}

#[test]
fn capacity_command_rejects_one_over_combined_working_buffers_before_output() {
    let mut command = audited_command();
    let sizes = preflight(&probe(&command), PROFILE).unwrap();
    let original = CommandBuffers::for_command(&command.intent, &sizes)
        .unwrap()
        .total()
        .unwrap();
    let ConfigMutationIntent::AuditedMutation(prepared) = &mut command.intent else {
        panic!("audited fixture");
    };
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &mut prepared.effect else {
        panic!("append fixture");
    };
    let old_capacity = commit.record.encrypted_blob.capacity();
    let at_capacity = old_capacity + OPERATION_BYTES - original;
    commit
        .record
        .encrypted_blob
        .try_reserve_exact(at_capacity - commit.record.encrypted_blob.len())
        .unwrap();
    assert_eq!(commit.record.encrypted_blob.capacity(), at_capacity);
    command
        .intent
        .validate_capacity(identity(), &key(), PROFILE)
        .unwrap();
    let at_sizes = preflight(&probe(&command), PROFILE).expect("inclusive combined buffer limit");
    assert_eq!(
        at_sizes, sizes,
        "capacity-only change preserves all encodings"
    );
    assert_eq!(
        CommandBuffers::for_command(&command.intent, &sizes)
            .unwrap()
            .total()
            .unwrap(),
        OPERATION_BYTES
    );
    let ConfigMutationIntent::AuditedMutation(prepared) = &mut command.intent else {
        unreachable!()
    };
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &mut prepared.effect else {
        unreachable!()
    };
    commit
        .record
        .encrypted_blob
        .try_reserve_exact(at_capacity + 1 - commit.record.encrypted_blob.len())
        .unwrap();
    assert_eq!(commit.record.encrypted_blob.capacity(), at_capacity + 1);
    prepared.verify_effect(&key()).unwrap();
    command
        .intent
        .validate_capacity(identity(), &key(), PROFILE)
        .unwrap();
    assert!(matches!(
        preflight(&probe(&command), PROFILE),
        Err(ForwardMutationRejection::CommandTooLarge)
    ));
}

#[test]
fn capacity_command_counts_unused_audit_and_string_capacities() {
    let mut command = command(128);
    let sizes = preflight(&probe(&command), PROFILE).unwrap();
    let initial = CommandBuffers::for_command(&command.intent, &sizes)
        .unwrap()
        .total()
        .unwrap();
    let ConfigMutationIntent::BoundedAppend { commit, .. } = &mut command.intent else {
        unreachable!()
    };
    let before = commit.record.principal.capacity();
    commit.record.principal.try_reserve_exact(8192).unwrap();
    let added = commit.record.principal.capacity() - before;
    commit.audit.try_reserve_exact(100).unwrap();
    let audit_backing = commit.audit.capacity() * std::mem::size_of::<crate::AuditRecord>();
    let after = CommandBuffers::for_command(&command.intent, &sizes)
        .unwrap()
        .total()
        .unwrap();
    assert_eq!(after - initial, added + audit_backing);
    assert_eq!(preflight(&probe(&command), PROFILE).unwrap(), sizes);
}
