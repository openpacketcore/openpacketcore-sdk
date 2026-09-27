//! Real encryption/attestation/reservation tests for the closed joint seam.
//! These do not claim that any supported store accepts wire10 or action16+bounded.
use super::*;

#[tokio::test]
async fn joint_submission_rejects_foreign_pool_and_overlapping_aliases() {
    let pool = ConfigPreparationPool::bounded_v1();
    let foreign = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let alias = prepared.clone();
    assert!(
        prepared
            .begin_submission(&foreign, ConfigCapacityProfile::BoundedV1)
            .is_err(),
        "JOINT_SUBMISSION_DESTINATION_POOL"
    );
    assert!(
        prepared
            .begin_submission(&pool, ConfigCapacityProfile::Legacy)
            .is_err(),
        "joint preparation cannot fall back to target9"
    );
    let guard = prepared
        .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
        .unwrap()
        .expect("bounded owner is mandatory");
    assert!(
        alias
            .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
            .is_err(),
        "JOINT_SUBMISSION_ALIAS_EXCLUSION"
    );
    let routed = Arc::clone(&guard);
    drop(guard);
    assert!(
        alias
            .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
            .is_err(),
        "routed alias keeps the original attempt active"
    );
    drop(routed);
    let retry = alias
        .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
        .unwrap()
        .unwrap();
    drop(retry);
    assert_eq!(
        alias.handle(),
        prepared.handle(),
        "slot reuse never re-identifies the original"
    );
}

#[tokio::test]
async fn joint_submission_command_clones_and_bytes_do_not_own_a_slot() {
    let pool = ConfigPreparationPool::bounded_v1();
    let other: Vec<_> = (0..7).map(|_| pool.try_reserve().unwrap()).collect();
    let prepared = signed(payload(&pool, br#"{"enabled":true}"#).await);
    let alias = prepared.clone();
    let command = prepared.command().clone();
    let commands = vec![command.clone(); 16];
    assert!(
        std::ptr::eq(command.handle(), prepared.handle()),
        "shared immutable command allocation"
    );
    assert_eq!(
        serde_json::to_vec(&command).unwrap(),
        prepared.encode().unwrap()
    );
    assert_eq!(
        opc_consensus::encode_bounded(&command).unwrap(),
        opc_consensus::encode_bounded(&prepared).unwrap()
    );
    let guard = prepared
        .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
        .unwrap()
        .unwrap();
    drop(prepared);
    drop(alias);
    assert!(
        pool.try_reserve().is_err(),
        "JOINT_SUBMISSION_GUARD_LIFETIME"
    );
    drop(guard);
    let released = pool.try_reserve().expect("JOINT_COMMAND_HAS_NO_SLOT_OWNER");
    assert!(
        pool.try_reserve().is_err(),
        "one original consumed one slot"
    );
    // Still-live native/routing/retained-description clones preserve exact data.
    for retained in &commands {
        assert!(retained == &command);
        retained
            .verify_bounded_running(&key(), identity(), event().caller)
            .unwrap();
    }
    drop(released);
    drop(other);
    all_slots_available(&pool);
}

#[tokio::test]
async fn joint_submission_recovery_needs_destination_reservation_not_proof_only() {
    let source = ConfigPreparationPool::bounded_v1();
    let destination = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&source, b"null").await);
    let bytes = prepared.encode().unwrap();
    let decoded = input(&bytes);
    assert!(
        decoded
            .begin_submission(&destination, ConfigCapacityProfile::BoundedV1)
            .is_err(),
        "JOINT_SUBMISSION_PROOF_IS_NOT_OWNER"
    );
    let held: Vec<_> = (0..7).map(|_| destination.try_reserve().unwrap()).collect();
    let recovered = recover(
        &bytes,
        destination.try_reserve().unwrap(),
        &destination,
        identity(),
        &key(),
        event().caller,
    )
    .unwrap();
    assert_eq!(recovered.handle(), prepared.handle());
    assert_eq!(recovered.encode().unwrap(), bytes);
    assert!(
        recovered
            .begin_submission(&source, ConfigCapacityProfile::BoundedV1)
            .is_err(),
        "recovery remains bound to actual destination"
    );
    let guard = recovered
        .begin_submission(&destination, ConfigCapacityProfile::BoundedV1)
        .unwrap()
        .unwrap();
    let retained = recovered.command().clone();
    drop(recovered);
    assert!(
        destination.try_reserve().is_err(),
        "recovered accepted owner remains live"
    );
    drop(guard);
    let slot = destination
        .try_reserve()
        .expect("JOINT_RECOVERED_OWNER_RELEASE");
    assert!(retained.handle() == prepared.handle());
    drop(slot);
    drop(held);
    all_slots_available(&destination);
}

#[tokio::test]
async fn joint_submission_legacy_target_wire_and_unreserved_path_are_unchanged() {
    let source = ConfigPreparationPool::bounded_v1();
    let mut prepared = signed(payload(&source, b"null").await);
    let commit = prepared.bounded_running().unwrap().commit().clone();
    prepared.command_mut().effect.encrypted_payload = Some(TargetPayloadV1::Running {
        commit: Box::new(commit),
        confirmation_ownership: None,
    });
    prepared.preparation = None;
    resign(&mut prepared);
    prepared.verify_effect(&key()).unwrap();
    #[derive(Serialize)]
    #[serde(rename = "PreparedTargetMutation")]
    struct OldPrepared<'a> {
        handle: &'a AuditOperationHandle,
        effect: &'a TargetEffectV1,
    }
    let old = OldPrepared {
        handle: prepared.handle(),
        effect: &prepared.command().effect,
    };
    let json = serde_json::to_vec(&old).unwrap();
    let wire = opc_consensus::encode_bounded(&old).unwrap();
    assert_eq!(
        prepared.encode().unwrap(),
        json,
        "JOINT_LEGACY_JSON_UNCHANGED"
    );
    assert_eq!(
        opc_consensus::encode_bounded(prepared.command()).unwrap(),
        wire,
        "JOINT_LEGACY_WIRE_UNCHANGED"
    );
    let decoded = PreparedTargetMutation::decode(&json).unwrap();
    assert!(decoded == prepared);
    assert!(decoded
        .begin_submission(&source, ConfigCapacityProfile::Legacy)
        .unwrap()
        .is_none());
    assert!(decoded
        .begin_submission(&source, ConfigCapacityProfile::BoundedV1)
        .is_err());
    for phase in [
        TargetAuditCommandV1::Admit(decoded.command().clone()),
        TargetAuditCommandV1::Apply(decoded.command().clone()),
    ] {
        assert_eq!(phase.minimum_command_version(), 9);
    }
    all_slots_available(&source);
}
