//! An independent expansion control for post-preparation output headroom.

use super::*;

const RECOVERY_HEADROOM_BYTES: usize = 524_288;

#[test]
fn config_capacity_957_recovery_headroom_accounts_for_encoded_output() {
    // Preserve a successful actual reserved encoder before the expanded case.
    recovery_case(false);
    let (compact, binding) = prepared(false).expect("genuine compact preparation");
    let PreparedConfigCommit { mut record, audit } = compact;
    let other = std::mem::size_of::<PreparedConfigCommit>()
        + record.principal.capacity()
        + record.plaintext_digest.capacity();
    let target = OPERATION_BYTES - RECOVERY_HEADROOM_BYTES - other;
    let original = record.encrypted_blob.clone();
    record
        .encrypted_blob
        .try_reserve_exact(target - record.encrypted_blob.len())
        .expect("capacity-only recovery expansion fixture");
    assert!(record.encrypted_blob == original);
    drop(original);
    assert_eq!(
        record.encrypted_blob.capacity() + other,
        OPERATION_BYTES - RECOVERY_HEADROOM_BYTES
    );
    binding
        .verify(&record, scope(), &key(), PROFILE)
        .expect("original exact record proof after capacity-only growth");
    let commit = match PreparedConfigCommit::prepare_for_profile(record, audit, &key(), PROFILE) {
        Ok(commit) => commit,
        Err(error) => {
            assert!(
                matches!(error.kind(), crate::PersistErrorKind::ConstraintViolation(message)
                    if message == "config preparation allocation exceeds working limit"),
                "valid expanded input may only be rejected by capacity admission"
            );
            return;
        }
    };
    commit.validate().expect("genuine finalized commit");
    let logical_time = commit.record.committed_at;
    let recovered = binding
        .recover(&commit.record, scope(), &key(), PROFILE)
        .expect("exact capacity evidence");
    let pool = opc_crypto::ConfigPreparationPool::bounded_v1();
    let owner = PreparationOwnership::recovered(
        pool.try_reserve().expect("local preparation reservation"),
        recovered,
    );
    assert!(owner.belongs_to(&pool, PROFILE, true));
    let mut prepared = audited_fixture(AuditedConfigEffect::BoundedAppend {
        commit: Box::new(commit),
        binding,
        resolution: None,
    });
    prepared.attach_preparation(owner);
    prepared.verify_effect(&key()).expect("original effect MAC");
    let command = command(
        ConfigMutationIntent::AuditedMutation(prepared.command().clone()),
        logical_time,
    );
    let encoded_bytes = command_bytes(&command);
    let recovery = prepared.encode().expect("reserved actual recovery encoder");
    assert!(recovery.len() <= crate::consensus::sqlite::CONFIG_CONSENSUS_LOG_ENTRY_MAX_BYTES);
    let AuditedConfigEffect::BoundedAppend { commit: source, .. } = &prepared.command().effect
    else {
        panic!("genuine audited append effect");
    };
    assert!(source.record.encrypted_blob.len() < RECOVERY_HEADROOM_BYTES);
    assert!(recovery.len() > RECOVERY_HEADROOM_BYTES);
    let source_bytes = heap_bytes(source);
    let recovery_bytes = recovery.capacity();
    let live_lower_bound = source_bytes
        .checked_add(recovery_bytes)
        .expect("finite simultaneous encoding lower bound");
    eprintln!(
        "CONFIG_CAPACITY_RECOVERY_HEADROOM source_bytes={source_bytes} recovery_bytes={recovery_bytes} command_bytes={encoded_bytes} live_lower_bound={live_lower_bound} proposed_operation_bound={OPERATION_BYTES}",
    );
    assert!(live_lower_bound <= OPERATION_BYTES,
        "CONFIG_CAPACITY_RECOVERY_HEADROOM: admitted source and actual encoded output exceed the proposed operation bound");
    std::hint::black_box((&prepared, &command, &recovery, &pool));
}
