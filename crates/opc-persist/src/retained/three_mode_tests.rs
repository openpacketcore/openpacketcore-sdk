//! Closed three-mode admission; no joint profile or migration is introduced.
use super::*;
use crate::audit_authority::{
    continuity::*, AuditAuthorityError, AuditLedgerLimits, AuditPrivacyKey,
};
use crate::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ConfigConsensusIdentity, ConfigConsensusNodeId, ConfigStore, ConsensusConfigStore,
};
use opc_crypto::ConfigCapacityProfile;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

const MODES: [RetainedConfigMode; 3] = [
    RetainedConfigMode::Legacy,
    RetainedConfigMode::BoundedV1,
    RetainedConfigMode::NetconfTargetsV1,
];
fn binding(mode: RetainedConfigMode) -> RetainedConfigBinding {
    let node = ConfigConsensusNodeId::new(1).unwrap();
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0x31; 32]),
        ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
    RetainedConfigBinding::new(topology, [0x41; 32], [0x42; 32])
        .unwrap()
        .with_profile(mode.target_profile())
        .with_capacity_profile(mode.capacity_profile())
}
fn options(path: &Path, mode: RetainedConfigMode) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        path,
        binding(mode),
        RetainedConfigDurability::Ephemeral,
        16 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .unwrap()
}
fn key() -> AuditKey {
    AuditKey::new([0x71; 32]).unwrap()
}
fn files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    std::fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    visit(root, root, &mut out);
    out
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn three_mode_binding_keeps_both_historical_transcripts_and_record_bytes() {
    let expected = [
        (
            "bbdef764b01c8f7e6ff1a0324d1af0170bf9bf4119d785d11c2a6aafe4aacb1a",
            "bd677bf676516b929e52687252489174e71d83c996f2c5f76bedf213624deac6",
        ),
        (
            "4083d78eea79ef518a254d029e2ac682820a381289dbeb8fa9116bb8b8521632",
            "023e12d05df372362567a3c7a0dbe8bb4e0d873ec9f3c07d8730aa575b95ae7f",
        ),
        (
            "b7ba166933843dbd1068696f21ae97eaf78377eb361da3a90b765acea1918f77",
            "63369a00bdbafabbb8f6017d77a91a7dbd0cde7c82b8909b8cc8396617de3862",
        ),
    ];
    for (mode, (digest, record_hash)) in MODES.into_iter().zip(expected) {
        let binding = binding(mode);
        assert_eq!(
            hex(&binding.digest(&key()).unwrap()),
            digest,
            "THREE_MODE_BINDING_BYTES"
        );
        let record = make_record(&binding, &key(), [1, 2, 3, 4, 5, 6], [0x61; 32], false).unwrap();
        assert_eq!(
            hex(&Sha256::digest(record)),
            record_hash,
            "THREE_MODE_RECORD_BYTES"
        );
        validate_record(&record, &binding, &key()).unwrap();
        for other in MODES.into_iter().filter(|other| *other != mode) {
            assert!(validate_record(&record, &self::binding(other), &key()).is_err());
        }
    }
}

#[tokio::test]
async fn three_mode_joint_selection_refuses_before_native_admission_or_creation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("joint.sqlite");
    let mut selected = options(&path, RetainedConfigMode::NetconfTargetsV1);
    selected.binding = selected
        .binding
        .with_capacity_profile(ConfigCapacityProfile::BoundedV1);
    assert!(matches!(
        selected.binding.mode(),
        Err(RetainedConfigError::Unsupported)
    ));
    assert!(matches!(
        selected.binding.digest(&key()),
        Err(RetainedConfigError::Unsupported)
    ));
    let before = files(dir.path());
    assert!(
        matches!(
            SqliteBackend::provision_config_authority(selected.clone(), key()).await,
            Err(RetainedConfigError::Unsupported)
        ),
        "THREE_MODE_JOINT_NATIVE_REFUSAL"
    );
    assert!(matches!(
        SqliteBackend::reopen_config_authority(selected, key()).await,
        Err(RetainedConfigError::Unsupported)
    ));
    assert_eq!(files(dir.path()), before, "THREE_MODE_JOINT_NO_FILES");
}

#[derive(Default)]
struct Checkpoint(Mutex<Option<AuditCheckpoint>>);
#[async_trait::async_trait]
impl AuditCheckpointPort for Checkpoint {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn compare_advance(
        &self,
        _: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        let mut current = self.0.lock().unwrap();
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        *current = Some(next);
        Ok(AuditCheckpointAdvance::Applied)
    }
}
fn policy(checkpoint: Arc<Checkpoint>) -> AuditContinuityPolicy {
    AuditContinuityPolicy::new(
        AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x72; 32]).unwrap()]).unwrap(),
        checkpoint,
        1,
        1,
    )
    .unwrap()
}

#[tokio::test]
async fn three_mode_native_admission_history_and_reopen_keep_the_selected_authority() {
    for (mode, storage, history_version) in [(MODES[0], 5, 1), (MODES[1], 6, 2), (MODES[2], 7, 1)] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("authority.sqlite");
        let selected = options(&path, mode);
        let checkpoint = Arc::new(Checkpoint::default());
        let privacy = AuditPrivacyKey::new([0x73; 32]).unwrap();
        for reopen in [false, true] {
            let backend = if reopen {
                SqliteBackend::reopen_config_authority(selected.clone(), key()).await
            } else {
                SqliteBackend::provision_config_authority(selected.clone(), key()).await
            }
            .unwrap();
            assert!(
                backend.load_latest().await.unwrap().is_none(),
                "THREE_MODE_AUTHENTICATED_EMPTY_READ"
            );
            {
                let shared = backend.conn();
                let conn = shared.lock().await;
                let revision: i64 = conn
                    .query_row(
                        "SELECT schema_version FROM config_raft_identity WHERE singleton=1",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(revision, storage, "THREE_MODE_NATIVE_STORAGE_REVISION");
                let history: Vec<u8> = conn
                    .query_row(
                        "SELECT state_json FROM config_raft_history_retention WHERE singleton=1",
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                let history: serde_json::Value = serde_json::from_slice(&history).unwrap();
                assert_eq!(history["format_version"], history_version);
                assert_eq!(
                    history.get("capacity_profile").and_then(|v| v.as_u64()),
                    (mode == RetainedConfigMode::BoundedV1).then_some(1)
                );
                let target: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='config_netconf_profile')", [], |r| r.get(0)).unwrap();
                let bounded: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='config_raft_capacity_records')", [], |r| r.get(0)).unwrap();
                assert_eq!(target, mode == RetainedConfigMode::NetconfTargetsV1);
                assert_eq!(bounded, mode == RetainedConfigMode::BoundedV1);
            }
            if mode == RetainedConfigMode::NetconfTargetsV1 {
                assert!(
                    matches!(
                        ConsensusConfigStore::open(
                            selected.binding.topology().clone(),
                            backend.clone(),
                            dir.path().join("snapshots"),
                            BTreeMap::new()
                        )
                        .await,
                        Err(crate::ConfigConsensusOpenError::AuditContinuityUnavailable)
                    ),
                    "THREE_MODE_TARGET_CONTINUITY_REQUIRED"
                );
            }
            let store = ConsensusConfigStore::open_with_audit_continuity(
                selected.binding.topology().clone(),
                backend,
                dir.path().join("snapshots"),
                BTreeMap::new(),
                policy(checkpoint.clone()),
            )
            .await
            .unwrap();
            store.initialize_cluster().await.unwrap();
            // This passes the real selected command framing, native log append,
            // apply and independent checkpoint paths in every mode.
            store
                .initialize_audit_authority(&privacy, AuditLedgerLimits::new(16, 4).unwrap())
                .await
                .unwrap();
            assert!(store.load_latest().await.unwrap().is_none());
            assert_eq!(store.capacity_profile(), mode.capacity_profile());
            assert!(checkpoint.0.lock().unwrap().is_some());
            store.shutdown().await.unwrap();
            drop(store);
        }
        let before = files(dir.path());
        for other in MODES.into_iter().filter(|other| *other != mode) {
            assert!(
                matches!(
                    SqliteBackend::reopen_config_authority(options(&path, other), key()).await,
                    Err(RetainedConfigError::Rejected)
                ),
                "THREE_MODE_CROSS_REOPEN_REFUSAL"
            );
            assert_eq!(
                files(dir.path()),
                before,
                "THREE_MODE_CROSS_REOPEN_NO_EFFECT"
            );
        }
    }
}
