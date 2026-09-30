//! Public Durable admission controls for successive bounded engine lifetimes.
//! Synthetic singleton fixtures exercise real retained admission and ciphertext
//! ownership; they do not qualify a whole-operation memory or latency bound.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use opc_crypto::{
    encrypt_reserved_bounded_config_envelope, AuthenticatedEnvelope, ConfigCapacityProfile,
    ConfigPreparationReservation,
};
use opc_key::{ConfigAad, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_persist::{
    AttestedConfigCommit, AuditKey, CommitRecord, CommitSource, ConfigConsensusClusterId,
    ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId, ConfigConsensusIdentity,
    ConfigConsensusNodeId, ConfigConsensusOpenError, ConfigConsensusTopology, ConfigStore,
    ConsensusConfigStore, PersistErrorKind, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigError, RetainedConfigOptions, SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

const PRINCIPAL: &str =
    "spiffe://qualification.invalid/tenant/synthetic/ns/test/sa/config/nf/test/instance/0";

fn topology() -> ConfigConsensusTopology {
    let node = ConfigConsensusNodeId::new(1).expect("synthetic node");
    ConfigConsensusTopology::try_new(
        ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0x91; 32]),
            ConfigConsensusConfigurationId::from_bytes([0x92; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        ),
        node,
        BTreeSet::from([node]),
    )
    .expect("singleton topology")
}

fn options(root: &Path) -> RetainedConfigOptions {
    options_for_profile(root, ConfigCapacityProfile::BoundedV1)
}

fn options_for_profile(root: &Path, profile: ConfigCapacityProfile) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology(), [0x93; 32], [0x94; 32])
            .expect("synthetic binding")
            .with_capacity_profile(profile),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("retained limits")
}

fn key() -> AuditKey {
    AuditKey::new([0x95; 32]).expect("synthetic audit key")
}

fn disk_fixture() -> PathBuf {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-engine-")
        .tempdir_in(scratch)
        .expect("private disk fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    root
}

async fn provision(root: &Path) -> SqliteBackend {
    SqliteBackend::provision_config_authority(options(root), key())
        .await
        .expect("native retained backend")
}

async fn open(
    root: &Path,
    backend: SqliteBackend,
) -> Result<ConsensusConfigStore, ConfigConsensusOpenError> {
    ConsensusConfigStore::open(topology(), backend, root.join("snapshots"), BTreeMap::new()).await
}

fn reserve(store: &ConsensusConfigStore) -> ConfigPreparationReservation {
    store
        .try_reserve_config_preparation()
        .expect("destination preparation admission")
        .expect("bounded preparation")
}

fn reserve_all(store: &ConsensusConfigStore) -> Vec<ConfigPreparationReservation> {
    let reservations = (0..8).map(|_| reserve(store)).collect();
    assert!(matches!(
        store
            .try_reserve_config_preparation()
            .expect_err("exact eight-slot pool")
            .kind(),
        PersistErrorKind::Unavailable
    ));
    reservations
}

async fn envelope(
    reservation: ConfigPreparationReservation,
) -> (AuthenticatedEnvelope, CommitRecord) {
    let tx_id = TxId::new();
    let committed_at = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
    let schema_digest = SchemaDigest::from_bytes([0x96; 32]);
    let aad = EnvelopeAad::config(
        TenantId::from_static("synthetic"),
        1,
        ConfigAad::new(
            tx_id,
            None,
            committed_at,
            PRINCIPAL,
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("synthetic-engine-lifetime").expect("key ID"),
            KeyPurpose::Config,
            TenantId::from_static("synthetic"),
            Zeroizing::new([0x97; 32]),
        )
        .expect("synthetic encryption key");
    let plaintext = br#"{"synthetic":true}"#;
    let encrypted =
        encrypt_reserved_bounded_config_envelope(reservation, &provider, &aad, plaintext)
            .await
            .expect("reserved bounded encryption");
    let record = CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at,
        principal: PRINCIPAL.into(),
        source: CommitSource::LocalOperator,
        schema_digest,
        plaintext_digest: Sha256::digest(plaintext).to_vec(),
        encrypted_blob: encrypted.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    (encrypted, record)
}

#[tokio::test]
async fn config_capacity_957_backend_clone_cannot_multiply_preparation_capacity() {
    let root = disk_fixture();
    let backend = provision(&root).await;
    let store = open(&root, backend.clone()).await.expect("first engine");
    let reservations = reserve_all(&store);
    assert!(backend
        .load_latest()
        .await
        .expect("ordinary clone read")
        .is_none());
    let second = open(&root, backend.clone()).await;
    let observed = match second {
        Ok(second) => {
            let extra = reserve_all(&second);
            second.shutdown().await.expect("duplicate engine cleanup");
            drop(extra);
            None
        }
        Err(error) => Some(error),
    };
    store.shutdown().await.expect("first engine shutdown");
    assert_eq!(
        observed,
        Some(ConfigConsensusOpenError::StorageUnavailable),
        "CONFIG_CAPACITY_ENGINE_CLONE_RED: a backend clone must not create another eight slots"
    );
    drop(store);
    assert_eq!(
        open(&root, backend.clone()).await.err(),
        Some(ConfigConsensusOpenError::StorageUnavailable),
        "reservations keep the original engine claimed after store drop"
    );
    drop(reservations);
    let next = open(&root, backend).await.expect("last owner released");
    let _next_reservations = reserve_all(&next);
    next.shutdown().await.expect("next engine shutdown");
}

#[tokio::test]
async fn config_capacity_957_racing_backend_clones_admit_one_engine() {
    let root = disk_fixture();
    let backend = provision(&root).await;
    let (left, right) = tokio::join!(open(&root, backend.clone()), open(&root, backend.clone()),);
    let mut admitted = 0;
    let mut refused = 0;
    for result in [left, right] {
        match result {
            Ok(store) => {
                admitted += 1;
                let _reservations = reserve_all(&store);
                store.shutdown().await.expect("racing engine cleanup");
            }
            Err(ConfigConsensusOpenError::StorageUnavailable) => refused += 1,
            Err(error) => panic!("unexpected open error: {error:?}"),
        }
    }
    assert_eq!((admitted, refused), (1, 1), "one exclusive engine claim");
    let next = open(&root, backend).await.expect("released racing owner");
    next.shutdown().await.expect("next engine shutdown");
}

#[tokio::test]
async fn config_capacity_957_post_shutdown_reservation_blocks_retained_reopen() {
    let root = disk_fixture();
    let store = open(&root, provision(&root).await)
        .await
        .expect("bounded engine");
    store.shutdown().await.expect("native engine shutdown");
    let reservations = reserve_all(&store);
    drop(store);
    let observed = SqliteBackend::reopen_config_authority(options(&root), key()).await;
    assert_eq!(
        observed.err(),
        Some(RetainedConfigError::InUse),
        "CONFIG_CAPACITY_ENGINE_RESERVATION_RED: post-shutdown preparations retain file admission"
    );
    drop(reservations);
    let backend = SqliteBackend::reopen_config_authority(options(&root), key())
        .await
        .expect("last preparation releases file admission");
    let next = open(&root, backend).await.expect("fresh retained engine");
    let _reservations = reserve_all(&next);
    next.shutdown().await.expect("next engine shutdown");
}

#[tokio::test]
async fn config_capacity_957_envelope_alias_blocks_retained_reopen_after_claim_drop() {
    let root = disk_fixture();
    let store = open(&root, provision(&root).await)
        .await
        .expect("bounded engine");
    let (encrypted, record) = envelope(reserve(&store)).await;
    let alias = encrypted.clone();
    let commit = AttestedConfigCommit::try_new(
        record,
        Vec::new(),
        encrypted.claim().expect("one-shot claim"),
    )
    .expect("typed reserved commit");
    drop(encrypted);
    drop(commit);
    store.shutdown().await.expect("native engine shutdown");
    drop(store);
    let observed = SqliteBackend::reopen_config_authority(options(&root), key()).await;
    assert_eq!(
        observed.err(),
        Some(RetainedConfigError::InUse),
        "CONFIG_CAPACITY_ENGINE_ALIAS_RED: ciphertext alias retains the original engine lifetime"
    );
    assert!(alias.claim().is_err(), "released claim cannot be reused");
    drop(alias);
    let backend = SqliteBackend::reopen_config_authority(options(&root), key())
        .await
        .expect("final ciphertext alias releases file admission");
    let next = open(&root, backend).await.expect("fresh retained engine");
    let _reservations = reserve_all(&next);
    next.shutdown().await.expect("next engine shutdown");
}

#[tokio::test]
async fn config_capacity_957_independent_backings_keep_foreign_reservations_foreign() {
    let first_root = disk_fixture();
    let second_root = disk_fixture();
    let first = open(&first_root, provision(&first_root).await)
        .await
        .expect("first independent engine");
    let second = open(&second_root, provision(&second_root).await)
        .await
        .expect("same topology on independently admitted backing");
    let mut reservations = reserve_all(&first);
    let second_reservations = reserve_all(&second);
    let (encrypted, record) = envelope(reservations.pop().expect("first destination owner")).await;
    let commit = AttestedConfigCommit::try_new(
        record,
        Vec::new(),
        encrypted.claim().expect("one-shot claim"),
    )
    .expect("typed reserved commit");
    let error = second
        .append_commit_idempotent(
            opc_consensus::ConsensusRequestId::from_bytes([0x98; 16]),
            commit,
        )
        .await
        .expect_err("foreign destination ownership");
    assert!(matches!(
        error.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));
    assert!(first.try_reserve_config_preparation().is_err());
    drop(encrypted);
    reservations.push(reserve(&first));
    assert!(second.try_reserve_config_preparation().is_err());
    drop(second_reservations);
    first.shutdown().await.expect("first engine shutdown");
    second.shutdown().await.expect("second engine shutdown");
}

#[tokio::test]
async fn config_capacity_957_failed_startup_releases_engine_claim_for_retry() {
    let root = disk_fixture();
    let backend = provision(&root).await;
    let invalid_snapshot_path = root.join("snapshot-file");
    std::fs::write(&invalid_snapshot_path, b"synthetic invalid directory").expect("fixture file");
    assert!(ConsensusConfigStore::open(
        topology(),
        backend.clone(),
        invalid_snapshot_path,
        BTreeMap::new(),
    )
    .await
    .is_err());
    let store = open(&root, backend)
        .await
        .expect("failed startup released claim");
    let _reservations = reserve_all(&store);
    store.shutdown().await.expect("retry engine shutdown");
}

#[tokio::test]
async fn config_capacity_957_legacy_backend_clones_preserve_existing_open_behavior() {
    let root = disk_fixture();
    let default_binding =
        RetainedConfigBinding::new(topology(), [0x93; 32], [0x94; 32]).expect("default binding");
    assert_eq!(
        default_binding.capacity_profile(),
        ConfigCapacityProfile::Legacy
    );
    let backend = SqliteBackend::provision_config_authority(
        options_for_profile(&root, default_binding.capacity_profile()),
        key(),
    )
    .await
    .expect("default legacy backend");
    let first = open(&root, backend.clone())
        .await
        .expect("first legacy engine");
    let second = open(&root, backend.clone())
        .await
        .expect("second legacy engine");
    assert!(first
        .try_reserve_config_preparation()
        .expect("legacy preparation")
        .is_none());
    assert!(second
        .try_reserve_config_preparation()
        .expect("legacy preparation")
        .is_none());
    assert!(backend
        .load_latest()
        .await
        .expect("ordinary clone read")
        .is_none());
    first.shutdown().await.expect("first legacy shutdown");
    second.shutdown().await.expect("second legacy shutdown");
}
