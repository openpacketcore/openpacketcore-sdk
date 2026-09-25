//! Envelope compatibility is independent of SQLite body authentication.
use super::*;
use crate::RetainedConfigProfile;

#[tokio::test]
async fn target_snapshot_envelope_preserves_legacy_bytes_and_requires_selected_profile() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path().join("source.sqlite");
    let payload = b"synthetic snapshot envelope byte fixture";
    std::fs::write(&raw, payload).unwrap();
    for (profile, revision) in [
        (RetainedConfigProfile::Legacy, 5u16),
        (RetainedConfigProfile::NetconfTargetsV1, 7u16),
    ] {
        let output = directory.path().join(format!("snapshot-{revision}.opc"));
        let (_, _, _cleanup) = envelope_snapshot_database_for_profile(&raw, &output, profile)
            .await
            .unwrap();
        let mut expected = payload.to_vec();
        expected.extend_from_slice(b"OPCCFG01");
        expected.extend_from_slice(&revision.to_be_bytes());
        expected.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        expected.extend_from_slice(&Sha256::digest(payload));
        assert_eq!(std::fs::read(&output).unwrap(), expected);
        assert!(verify_snapshot_envelope_for_profile(&output, profile)
            .await
            .is_ok());
        let other = match profile {
            RetainedConfigProfile::Legacy => RetainedConfigProfile::NetconfTargetsV1,
            RetainedConfigProfile::NetconfTargetsV1 => RetainedConfigProfile::Legacy,
        };
        assert!(verify_snapshot_envelope_for_profile(&output, other)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn target_snapshot_envelope_rejects_truncation_substitution_and_unknown_revision() {
    let directory = tempfile::tempdir().unwrap();
    let raw = directory.path().join("source.sqlite");
    let payload = b"synthetic snapshot envelope byte fixture";
    std::fs::write(&raw, payload).unwrap();
    let output = directory.path().join("snapshot.opc");
    let profile = RetainedConfigProfile::NetconfTargetsV1;
    let (_, _, _cleanup) = envelope_snapshot_database_for_profile(&raw, &output, profile)
        .await
        .unwrap();
    let original = std::fs::read(&output).unwrap();
    let mut attacks = vec![
        Vec::new(),
        original[..8].to_vec(),
        original[..original.len() - 1].to_vec(),
    ];
    let mut substituted = original.clone();
    substituted[0] ^= 1;
    attacks.push(substituted);
    let mut trailing = original.clone();
    trailing.push(0);
    attacks.push(trailing);
    for revision in [0u16, 5, 6, 8, 9, u16::MAX] {
        let mut altered = original.clone();
        altered[payload.len() + 8..payload.len() + 10].copy_from_slice(&revision.to_be_bytes());
        attacks.push(altered);
    }
    for bytes in attacks {
        std::fs::write(&output, bytes).unwrap();
        assert!(verify_snapshot_envelope_for_profile(&output, profile)
            .await
            .is_err());
    }
    std::fs::write(&output, original).unwrap();
    assert!(verify_snapshot_envelope_for_profile(&output, profile)
        .await
        .is_ok());
}
