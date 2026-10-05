use super::support::*;
use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::types::*;
use crate::consensus::PreparedAuditedMutation;
use serde::Serialize;

// Golden production source: 2523e9c514d7e3c1c100c9ddc52d86b730650bf3.
// Reproduce in a clean checkout of that commit with this revision's Git objects
// available. The two immutable blobs below contain only the committed legacy
// test harness; neither depends on bounded representations or changes production.
//
// mkdir -p crates/opc-persist/src/consensus/capacity_tests
// git cat-file blob a4cc6966fae5933b8ff75b8210124db968705b48 > crates/opc-persist/src/consensus/capacity_tests/legacy_support.rs
// git cat-file blob 279812504da680051a732393b59358951775ccd3 > crates/opc-persist/src/consensus/capacity_tests/legacy_fixtures.rs
// printf '\n#[cfg(test)]\n#[path = "capacity_tests/legacy_support.rs"]\nmod legacy_support;\n#[cfg(test)]\n#[path = "capacity_tests/legacy_fixtures.rs"]\nmod legacy_fixtures;\n' >> crates/opc-persist/src/consensus/mod.rs
// OPC_PERSIST_LEGACY_CAPTURE="$PWD/crates/opc-persist/src/consensus/capacity_tests/legacy.json" timeout 120s cargo test --locked -p opc-persist --lib consensus::legacy_fixtures::capture_legacy_bytes -- --exact --ignored
//
// The ordinary regression only compares; capture requires the ignored test and
// an explicit destination. Preserve the original rows when extending the shapes.
#[test]
fn legacy_bytes() {
    let actual = super::legacy_fixtures::capture();
    let expected: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("legacy.json")).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn legacy_serde_keeps_sequences_even_for_formats_with_a_distinct_byte_type() {
    struct NoBytes;
    impl serde_json::ser::Formatter for NoBytes {
        fn write_byte_array<W: ?Sized + std::io::Write>(
            &mut self,
            _: &mut W,
            _: &[u8],
        ) -> std::io::Result<()> {
            Err(std::io::Error::other(
                "unexpected byte-string representation",
            ))
        }
    }
    for (_, command) in super::legacy_fixtures::commands() {
        let mut encoded = Vec::new();
        command
            .serialize(&mut serde_json::Serializer::with_formatter(
                &mut encoded,
                NoBytes,
            ))
            .unwrap();
        assert_eq!(encoded, serde_json::to_vec(&command).unwrap());
    }
    for audited in [false, true] {
        assert!(bounded_command(audited, None)
            .serialize(&mut serde_json::Serializer::with_formatter(
                Vec::new(),
                NoBytes
            ))
            .is_err());
    }
}

#[test]
fn legacy_effect_and_recovery_json_ceilings_are_inclusive() {
    use crate::audit_authority::AuditAuthorityError;
    // Recovery decoding does not validate labels until submission. Pin that
    // existing representational ceiling as well as valid command admission.
    let mut effect = AuditedConfigEffect::RollbackPoint {
        tx_id: tx(),
        label: Some(ValidatedRollbackLabel(String::new())),
    };
    let overhead = serde_json::to_vec(&effect).unwrap().len();
    let AuditedConfigEffect::RollbackPoint { label, .. } = &mut effect else {
        unreachable!()
    };
    label.as_mut().unwrap().0 = "x".repeat(16 * 1024 * 1024 - overhead);
    assert_eq!(serde_json::to_vec(&effect).unwrap().len(), 16 * 1024 * 1024);
    let expected = crate::audit_authority::ledger::authenticate(
        &key(),
        b"openpacketcore/management-audit/config-mutation/v1\0",
        &effect,
    )
    .unwrap();
    assert_eq!(effect.digest(&key()).unwrap(), expected);
    effect.verify(&key(), &expected).unwrap();
    assert_eq!(
        effect.verify(&key(), &[0; 32]),
        Err(AuditAuthorityError::BindingMismatch)
    );
    let AuditedConfigEffect::RollbackPoint { label, .. } = &mut effect else {
        unreachable!()
    };
    label.as_mut().unwrap().0.push('x');
    assert_eq!(
        effect.digest(&key()),
        Err(AuditAuthorityError::InvalidInput)
    );

    let mut prepared = PreparedAuditedMutation {
        handle: handle(None),
        effect: AuditedConfigEffect::RollbackPoint {
            tx_id: tx(),
            label: Some(ValidatedRollbackLabel(String::new())),
        },
    };
    let overhead = serde_json::to_vec(&prepared).unwrap().len();
    let AuditedConfigEffect::RollbackPoint { label, .. } = &mut prepared.effect else {
        unreachable!()
    };
    label.as_mut().unwrap().0 = "x".repeat(16 * 1024 * 1024 - overhead);
    let at = prepared.encode().unwrap();
    assert_eq!(at.len(), 16 * 1024 * 1024);
    assert_eq!(PreparedAuditedMutation::decode(&at).unwrap(), prepared);
    let AuditedConfigEffect::RollbackPoint { label, .. } = &mut prepared.effect else {
        unreachable!()
    };
    label.as_mut().unwrap().0.push('x');
    assert_eq!(prepared.encode(), Err(AuditAuthorityError::InvalidInput));
    let mut over = at;
    over.push(b' ');
    assert_eq!(
        PreparedAuditedMutation::decode(&over).unwrap_err(),
        AuditAuthorityError::InvalidInput
    );
}
