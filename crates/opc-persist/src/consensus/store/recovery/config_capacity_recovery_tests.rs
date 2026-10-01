use super::*;

fn identity(marker: u8) -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        crate::ConfigConsensusClusterId::from_bytes([marker; 32]),
        crate::ConfigConsensusConfigurationId::from_bytes([0x92; 32]),
        crate::ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    )
}

fn key() -> AuditKey {
    AuditKey::new([0x93; 32]).expect("synthetic key")
}

fn handle() -> ConfigCommitRecoveryHandle {
    ConfigCommitRecoveryHandle::issue(
        &key(),
        identity(0x91),
        opc_crypto::ConfigCapacityProfile::Legacy,
        ConfigConsensusRequestId::from_bytes([0x94; 16]),
        [0x95; 32],
        "synthetic caller",
    )
    .expect("issue original handle")
}

#[test]
fn config_capacity_957_recovery_encoding_is_exact_and_redacted() {
    let original = handle();
    assert_eq!(
        original.as_bytes().len(),
        ConfigCommitRecoveryHandle::ENCODED_BYTES
    );
    let recovered = ConfigCommitRecoveryHandle::from_bytes(original.as_bytes()).expect("parse");
    assert_eq!(recovered, original);
    assert_eq!(
        format!("{original:?}"),
        "ConfigCommitRecoveryHandle(<redacted>)"
    );
    for bytes in [0, HANDLE_BYTES - 1, HANDLE_BYTES + 1] {
        assert!(ConfigCommitRecoveryHandle::from_bytes(&vec![0; bytes]).is_err());
    }
    recovered
        .verify_scope(
            &key(),
            identity(0x91),
            opc_crypto::ConfigCapacityProfile::Legacy,
        )
        .expect("scope");
    recovered
        .verify_caller(&key(), "synthetic caller")
        .expect("caller");
    assert!(recovered.matches_digest(&[0x95; 32]));
    assert!(!recovered.matches_digest(&[0x96; 32]));
}

#[test]
fn config_capacity_957_recovery_every_changed_byte_rejects() {
    let original = handle();
    for index in 0..HANDLE_BYTES {
        let mut encoded = original.encoded;
        encoded[index] ^= 1;
        if let Ok(changed) = ConfigCommitRecoveryHandle::from_bytes(&encoded) {
            assert!(
                changed
                    .verify_scope(
                        &key(),
                        identity(0x91),
                        opc_crypto::ConfigCapacityProfile::Legacy
                    )
                    .is_err(),
                "modified handle must fail authentication"
            );
        }
    }
}

#[test]
fn config_capacity_957_recovery_scope_and_caller_are_separately_required() {
    let original = handle();
    let profile = opc_crypto::ConfigCapacityProfile::Legacy;
    assert!(original
        .verify_scope(&key(), identity(0x96), profile)
        .is_err());
    assert!(original
        .verify_scope(
            &key(),
            identity(0x91),
            opc_crypto::ConfigCapacityProfile::BoundedV1
        )
        .is_err());
    let other_key = AuditKey::new([0x97; 32]).expect("other key");
    assert!(original
        .verify_scope(&other_key, identity(0x91), profile)
        .is_err());
    let other_epoch = AuditKey::new_with_epoch([0x93; 32], 2).expect("same material, next epoch");
    assert!(original
        .verify_scope(&other_epoch, identity(0x91), profile)
        .is_err());
    assert!(original.verify_caller(&key(), "different caller").is_err());

    // A valid tag is insufficient when the claimed authority/profile differs.
    // Re-sign each scope field independently to exercise semantic checks too.
    for offset in [0, 4, 6, 8, 40, 72, 80] {
        let mut changed = original.clone();
        changed.encoded[offset] ^= 1;
        let mut mac = handle_mac(&key()).expect("MAC");
        mac.update(&changed.encoded[..HANDLE_BODY_BYTES]);
        changed.encoded[HANDLE_BODY_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
        assert!(changed
            .verify_scope(&key(), identity(0x91), profile)
            .is_err());
    }
}
