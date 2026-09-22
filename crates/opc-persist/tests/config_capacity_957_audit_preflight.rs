//! Audited capacity admission on retained native Durable singleton storage.
//! This exercises public preparation/admission APIs, not production transport.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_persist::audit_authority::{
    AuditAdmission, AuditAuthorityError, AuditCaller, AuditLedgerLimits, AuditOperationReceipt,
    AuditOperationState, AuditPrivacyKey,
};
use opc_persist::{
    AttestedConfigCommit, AuditKey, CommitRecord, CommitSource, ConfigConsensusClusterId,
    ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId, ConfigConsensusIdentity,
    ConfigConsensusNodeId, ConfigConsensusTopology, ConfigStore, ConsensusConfigStore,
    ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
    RetainedConfigBinding, RetainedConfigDurability, RetainedConfigOptions, SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

const PRINCIPAL: &str =
    "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/a";

fn commit(
    bytes: usize,
    parent: Option<TxId>,
    version: u64,
) -> (AttestedConfigCommit, CommitRecord) {
    let plaintext = format!(
        "\"{}\"",
        "q".repeat(bytes.checked_sub(2).expect("JSON length"))
    );
    assert_eq!(plaintext.len(), bytes);
    let tx_id = TxId::new();
    let committed_at = Timestamp::now_utc();
    let schema_digest = SchemaDigest::from_bytes([0xE1; 32]);
    let aad = EnvelopeAad::config(
        TenantId::from_static("test"),
        version,
        ConfigAad::new(
            tx_id,
            parent,
            committed_at,
            PRINCIPAL,
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let key = KeyHandle::new(
        KeyId::new("synthetic-audit-capacity-key").expect("key ID"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xE2; 32]),
    );
    let encrypted = opc_crypto::encrypt_attested_envelope_with_handle_and_nonce(
        &key,
        &aad,
        plaintext.as_bytes(),
        [u8::try_from(version).expect("fixture nonce"); 12],
    )
    .expect("actual authenticated encryption");
    let record = CommitRecord {
        tx_id,
        parent_tx_id: parent,
        version: ConfigVersion::new(version),
        committed_at,
        principal: PRINCIPAL.into(),
        source: CommitSource::LocalOperator,
        schema_digest,
        plaintext_digest: Sha256::digest(plaintext.as_bytes()).to_vec(),
        encrypted_blob: encrypted.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let commit = AttestedConfigCommit::try_new(
        record.clone(),
        Vec::new(),
        encrypted.claim().expect("fresh encryption claim"),
    )
    .expect("attested input");
    (commit, record)
}

fn disk_fixture() -> PathBuf {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit local or hosted scratch root is required");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-audit-preflight-")
        .tempdir_in(scratch)
        .expect("private retained fixture")
        .keep();
    let output = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector required");
    assert!(output.status.success());
    let filesystem = std::str::from_utf8(&output.stdout)
        .expect("filesystem encoding")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    root
}

async fn open(root: &Path) -> ConsensusConfigStore {
    let node = ConfigConsensusNodeId::new(1).expect("synthetic node");
    let topology = ConfigConsensusTopology::try_new(
        ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0xE3; 32]),
            ConfigConsensusConfigurationId::from_bytes([0xE4; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        ),
        node,
        BTreeSet::from([node]),
    )
    .expect("singleton topology");
    let options = RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology.clone(), [0xE5; 32], [0xE6; 32]).expect("binding"),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("retained options");
    let backend = SqliteBackend::provision_config_authority(
        options,
        AuditKey::new([0xE7; 32]).expect("synthetic audit key"),
    )
    .await
    .expect("native Durable backend");
    let store =
        ConsensusConfigStore::open(topology, backend, root.join("snapshots"), BTreeMap::new())
            .await
            .expect("retained store");
    store.initialize_cluster().await.expect("admission");
    store
        .probe_durable_readiness()
        .await
        .expect("leader and apply");
    store
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0xE8; 32]).expect("synthetic privacy key")
}

fn caller() -> AuditCaller {
    AuditCaller::project(&privacy(), "test", PRINCIPAL).expect("synthetic caller")
}

fn event(marker: u8) -> ManagementAuditEventRecord {
    ManagementAuditEventRecord::try_new(
        [marker; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .expect("synthetic event time"),
        "test",
        PRINCIPAL,
        ManagementAuditTransportCode::Gnmi,
        ManagementAuditOperationCode::Update,
        ManagementAuditOutcomeCode::Intent,
        None,
        ["/fixture:config"],
        Some("synthetic-capacity-transaction"),
    )
    .expect("synthetic event")
}

fn applied(result: AuditAdmission) -> AuditOperationReceipt {
    match result {
        AuditAdmission::Applied(receipt) => receipt,
        _ => panic!("expected authoritative audit receipt"),
    }
}

fn effects(root: &Path) -> ([i64; 4], Vec<u8>, Vec<u8>) {
    let reader = rusqlite::Connection::open_with_flags(
        root.join("config.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("independent read-only observer");
    let counts = [
        "config_history",
        "audit_trail",
        "config_raft_log",
        "config_raft_request_outcomes",
    ]
    .map(|table| {
        reader
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("effect count")
    });
    let (state, mac) = reader
        .query_row(
            "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("exact authenticated audit state");
    (counts, state, mac)
}

async fn exercise(local_only: bool) {
    let root = disk_fixture();
    let store = open(&root).await;
    store
        .initialize_audit_authority(&privacy(), AuditLedgerLimits::new(12, 4).expect("limits"))
        .await
        .expect("admitted ledger");
    let (input, expected) = commit(262_144, None, 1);
    let before = effects(&root);
    let prepared = store
        .prepare_audited_commit(&privacy(), &event(1), input, Duration::from_secs(60))
        .expect("within-budget positive control");
    assert!(
        effects(&root) == before,
        "preparation must have no durable effects"
    );
    let receipt = applied(if local_only {
        store
            .admit_audit_operation_local(prepared.handle(), caller())
            .await
    } else {
        store
            .admit_audit_operation(prepared.handle(), caller())
            .await
    });
    let committed = applied(if local_only {
        store
            .submit_audited_mutation_local(&prepared, &receipt, caller())
            .await
    } else {
        store
            .submit_audited_mutation(&prepared, &receipt, caller())
            .await
    });
    assert_eq!(
        committed.state(),
        AuditOperationState::Committed { version: 1 }
    );
    let observed = store
        .load_latest()
        .await
        .expect("readback")
        .expect("committed head");
    assert!(
        observed.record == expected,
        "positive control has exact encrypted readback"
    );
    let before = effects(&root);
    let (input, _) = commit(1_572_864, Some(expected.tx_id), 2);
    let result =
        store.prepare_audited_commit(&privacy(), &event(2), input, Duration::from_secs(60));
    assert!(
        effects(&root) == before,
        "preparation has not submitted anything"
    );
    match result {
        Err(AuditAuthorityError::InvalidInput) => {
            let observed = store
                .load_latest()
                .await
                .expect("readback")
                .expect("previous head");
            assert!(
                observed.record == expected,
                "oversize rejection retains exact head"
            );
            assert!(
                effects(&root) == before,
                "oversize rejects before audit or log effects"
            );
        }
        Ok(prepared) => {
            // Diagnose the original late rejection before the desired failure.
            // A failed setup or unacknowledged intent is not this detector's RED.
            let receipt = applied(if local_only {
                store
                    .admit_audit_operation_local(prepared.handle(), caller())
                    .await
            } else {
                store
                    .admit_audit_operation(prepared.handle(), caller())
                    .await
            });
            assert_eq!(receipt.state(), AuditOperationState::Intent);
            let admitted = effects(&root);
            assert!(
                admitted.1 != before.1,
                "oversize intent was durably admitted"
            );
            assert!(
                admitted.0[2] > before.0[2],
                "intent added a durable log entry"
            );
            let rejected = if local_only {
                store
                    .submit_audited_mutation_local(&prepared, &receipt, caller())
                    .await
            } else {
                store
                    .submit_audited_mutation(&prepared, &receipt, caller())
                    .await
            };
            assert!(matches!(
                rejected,
                AuditAdmission::Rejected(AuditAuthorityError::InvalidInput)
            ));
            let retained = store
                .lookup_audit_operation(prepared.handle(), caller())
                .await
                .expect("exact retained lookup")
                .expect("admitted intent");
            assert_eq!(retained.state(), AuditOperationState::Intent);
            let observed = store
                .load_latest()
                .await
                .expect("readback")
                .expect("previous head");
            assert!(
                observed.record == expected,
                "late rejection did not append config"
            );
            assert!(
                effects(&root) == admitted,
                "late preflight cannot undo admitted intent"
            );
            store.shutdown().await.expect("shutdown baseline fixture");
            panic!("CONFIG_CAPACITY_AUDIT_PREFLIGHT_RED: reject oversized preparation before issuing an admissible audit handle");
        }
        Err(_) => panic!("unexpected preparation failure"),
    }
    store.shutdown().await.expect("shutdown fixture");
}

#[tokio::test]
async fn config_capacity_957_audited_local_preparation_rejects_before_intent() {
    exercise(true).await;
}

#[tokio::test]
async fn config_capacity_957_audited_routed_preparation_rejects_before_intent() {
    exercise(false).await;
}
