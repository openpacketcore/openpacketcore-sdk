//! Legacy retained-opening compatibility controls for RFC 019 target profiles.
//! All identities and key material are synthetic. These controls do not qualify
//! the new target profile, checkpoint freshness, or configuration effects.

use hmac::{Hmac, KeyInit, Mac};
use opc_persist::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, RetainedConfigBinding, RetainedConfigDurability, RetainedConfigError,
    RetainedConfigOptions, SqliteBackend,
};
use sha2::Sha256;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

struct LegacyBinding {
    key_epoch: u64,
    local_node: u64,
    members: &'static [u64],
    digest: &'static str,
}

fn fixtures() -> [LegacyBinding; 3] {
    [
        LegacyBinding {
            key_epoch: 1,
            local_node: 1,
            members: &[1],
            digest: "bbdef764b01c8f7e6ff1a0324d1af0170bf9bf4119d785d11c2a6aafe4aacb1a",
        },
        LegacyBinding {
            key_epoch: 2,
            local_node: 1,
            members: &[1],
            digest: "2829fcdc17f46e5416259fb1f984e900b66089532e0ec84a924b4576fb64ee55",
        },
        LegacyBinding {
            key_epoch: 1,
            local_node: 3,
            members: &[1, 3, 5],
            digest: "022923f3bb65068c4f5a8c1a702e622535eec974c79acdd24040053d9a4f7733",
        },
    ]
}

fn options(path: &Path, fixture: &LegacyBinding, backing: u8) -> RetainedConfigOptions {
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x31; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology = ConfigConsensusTopology::try_new(
        identity,
        ConfigConsensusNodeId::new(fixture.local_node).unwrap(),
        fixture
            .members
            .iter()
            .map(|node| ConfigConsensusNodeId::new(*node).unwrap())
            .collect::<BTreeSet<_>>(),
    )
    .unwrap();
    RetainedConfigOptions::new(
        path,
        RetainedConfigBinding::new(topology, [backing; 32], [0x42; 32]).unwrap(),
        RetainedConfigDurability::Ephemeral,
        16 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap()
}

fn key(fixture: &LegacyBinding) -> AuditKey {
    AuditKey::new_with_epoch([0x71; 32], fixture.key_epoch).unwrap()
}

fn assert_legacy_record(record: &[u8], fixture: &LegacyBinding, repair: bool) {
    assert_eq!(record.len(), 153, "legacy admission size changed");
    assert_eq!(&record[..8], b"OPCRET01");
    let expected: Vec<u8> = fixture
        .digest
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    assert_eq!(&record[8..40], expected.as_slice());
    assert_eq!(record[72], u8::from(repair));
    // The nonce and filesystem identity vary. Authenticate the actual bytes
    // with the frozen predecessor domain and the synthetic fixture key.
    let mut mac = Hmac::<Sha256>::new_from_slice(&[0x71; 32]).unwrap();
    mac.update(b"openpacketcore/config-retained-admission/v1\0");
    mac.update(&record[..121]);
    mac.verify_slice(&record[121..]).unwrap();
}

#[tokio::test]
async fn legacy_retained_binding_bytes_and_disposition_survive_reopen() {
    for fixture in fixtures() {
        for repair in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("legacy.sqlite");
            let options = options(&path, &fixture, 0x41);
            let backend = if repair {
                SqliteBackend::provision_config_member_repair(options.clone(), key(&fixture))
                    .await
                    .unwrap()
            } else {
                SqliteBackend::provision_config_authority(options.clone(), key(&fixture))
                    .await
                    .unwrap()
            };
            drop(backend);
            let record_path = dir.path().join("legacy.sqlite.opc-retained");
            let before = std::fs::read(&record_path).unwrap();
            assert_legacy_record(&before, &fixture, repair);
            let reopened = SqliteBackend::reopen_config_authority(options, key(&fixture))
                .await
                .unwrap();
            drop(reopened);
            assert_eq!(std::fs::read(&record_path).unwrap(), before);
        }
    }
}

#[tokio::test]
async fn legacy_wrong_backing_rejection_preserves_storage_and_releases_admission() {
    let fixture = &fixtures()[0];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.sqlite");
    drop(
        SqliteBackend::provision_config_authority(options(&path, fixture, 0x41), key(fixture))
            .await
            .unwrap(),
    );
    let snapshot = || {
        std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before = snapshot();
    let rejected =
        SqliteBackend::reopen_config_authority(options(&path, fixture, 0x43), key(fixture)).await;
    assert!(matches!(rejected, Err(RetainedConfigError::Rejected)));
    assert_eq!(snapshot(), before, "rejection changed original storage");
    drop(
        SqliteBackend::reopen_config_authority(options(&path, fixture, 0x41), key(fixture))
            .await
            .unwrap(),
    );
}
