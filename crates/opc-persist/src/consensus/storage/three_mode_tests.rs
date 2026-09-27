//! Cross-profile snapshot envelope refusal at the real storage codec boundary.
use super::*;
#[tokio::test]
async fn three_mode_snapshot_footers_keep_legacy_bytes_and_refuse_every_cross_profile() {
    let dir = tempfile::tempdir().unwrap();
    let body = b"synthetic snapshot envelope body";
    let raw = dir.path().join("raw");
    tokio::fs::write(&raw, body).await.unwrap();
    let identity = ConsensusIdentity::new(
        crate::ConfigConsensusClusterId::from_bytes([0x31; 32]),
        crate::ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
        crate::ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let key = AuditKey::new([0x71; 32]).unwrap();
    let modes = [
        RetainedConfigMode::Legacy,
        RetainedConfigMode::BoundedV1,
        RetainedConfigMode::NetconfTargetsV1,
    ];
    for (mode, revision) in [(modes[0], 5_u16), (modes[1], 6), (modes[2], 7)] {
        let path = dir.path().join(format!("snapshot-{revision}"));
        let (checksum, total, _cleanup) =
            envelope_snapshot_database(&raw, &path, mode, identity, &key)
                .await
                .unwrap();
        assert_eq!(total, body.len() as u64 + SNAPSHOT_FOOTER_BYTES);
        let bytes = tokio::fs::read(&path).await.unwrap();
        assert_eq!(&bytes[..body.len()], body);
        assert_eq!(&bytes[body.len()..body.len() + 8], SNAPSHOT_FOOTER_MAGIC);
        assert_eq!(
            &bytes[body.len() + 8..body.len() + 10],
            &revision.to_be_bytes(),
            "THREE_MODE_SNAPSHOT_REVISION"
        );
        if mode != RetainedConfigMode::BoundedV1 {
            assert_eq!(
                checksum,
                <[u8; 32]>::from(Sha256::digest(body)),
                "THREE_MODE_SNAPSHOT_OLD_CHECKSUM"
            );
        }
        assert_eq!(
            verify_snapshot_envelope(&path, mode, identity, &key)
                .await
                .unwrap(),
            (body.len() as u64, checksum, total)
        );
        for other in modes.into_iter().filter(|other| *other != mode) {
            assert!(
                verify_snapshot_envelope(&path, other, identity, &key)
                    .await
                    .is_err(),
                "THREE_MODE_SNAPSHOT_CROSS_REFUSAL"
            );
        }
        let mut changed = bytes;
        changed[0] ^= 1;
        tokio::fs::write(&path, changed).await.unwrap();
        assert!(
            verify_snapshot_envelope(&path, mode, identity, &key)
                .await
                .is_err(),
            "THREE_MODE_SNAPSHOT_INTEGRITY"
        );
    }
}
