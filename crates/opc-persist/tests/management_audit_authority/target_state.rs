//! Retained target state transitions through the existing audit apply boundary.
use super::*;
use crate::audit_authority::continuity::checkpoint::CheckpointBody;
use crate::audit_authority::continuity::AuditSigningKey;
use crate::audit_authority::ledger::{authenticate, HandleBody};
use crate::audit_authority::{
    AuditOperationBinding, AuditPrivacyKey, NetconfAppliedOutcome, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::{
    PreparedTargetMutation, TargetAuditCommandV1, TargetEffectV1, TargetExpectationV1,
    TargetResolutionV1,
};
use crate::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ConfigConsensusNodeId, ConfigConsensusTopology, ManagementAuditEventRecord,
    ManagementAuditInstant, ManagementAuditOperationCode, ManagementAuditOutcomeCode,
    ManagementAuditTimeSourceCode, ManagementAuditTransportCode, RetainedConfigBinding,
    RetainedConfigDurability, RetainedConfigOptions, RetainedConfigProfile, SqliteBackend,
};
use serde_json::Value;
use std::{collections::BTreeSet, time::Duration};

struct Fixture {
    directory: tempfile::TempDir,
    backend: SqliteBackend,
    identity: ConfigConsensusIdentity,
    key: AuditKey,
    keys: AuditKeyRing,
    privacy: AuditPrivacyKey,
}

impl Fixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0x41; 32]),
            ConfigConsensusConfigurationId::from_bytes([0x42; 32]),
            ConfigConsensusConfigurationEpoch::new(1).unwrap(),
        );
        let node = ConfigConsensusNodeId::new(1).unwrap();
        let topology =
            ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
        let key = AuditKey::new([0x43; 32]).unwrap();
        let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x44; 32]).unwrap()]).unwrap();
        let options = RetainedConfigOptions::new(
            directory.path().join("authority.sqlite"),
            RetainedConfigBinding::new(topology, [0x45; 32], [0x46; 32])
                .unwrap()
                .with_profile(RetainedConfigProfile::NetconfTargetsV1),
            RetainedConfigDurability::Ephemeral,
            16 * 1024 * 1024,
            Duration::from_secs(30),
        )
        .unwrap();
        let backend = SqliteBackend::provision_config_authority(options, key.clone())
            .await
            .unwrap();
        let fixture = Self {
            directory,
            backend,
            identity,
            key,
            keys,
            privacy: AuditPrivacyKey::new([0x47; 32]).unwrap(),
        };
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        fixture
            .apply(
                &conn,
                AuditCommand::InitializeWithContinuity {
                    projection: fixture.event(1).projection,
                    limits: AuditLedgerLimits::new(96, 32).unwrap(),
                    initial_epoch: 1,
                },
                100,
            )
            .unwrap();
        fixture.checkpoint(&conn);
        drop(conn);
        fixture
    }

    fn event(&self, request: u8) -> ProjectedAuditEvent {
        let event = ManagementAuditEventRecord::try_new(
            [request; 16],
            ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
                .unwrap(),
            "fixture-tenant",
            "fixture-principal",
            ManagementAuditTransportCode::NetconfSsh,
            ManagementAuditOperationCode::Exec,
            ManagementAuditOutcomeCode::Intent,
            None::<&str>,
            ["/fixture:configuration"],
            Some("fixture-target"),
        )
        .unwrap();
        ProjectedAuditEvent::project(&self.privacy, &event).unwrap()
    }

    fn apply(
        &self,
        conn: &Connection,
        command: AuditCommand,
        now: i64,
    ) -> Result<(), ConfigMutationFailure> {
        let tx = conn.unchecked_transaction().unwrap();
        let result = apply_sync(
            &tx,
            &self.key,
            self.identity,
            &command,
            now,
            Some(&self.keys),
        )
        .expect("audit transaction I/O");
        // A definite retained rejection is also committed. An I/O failure above
        // drops the transaction instead of publishing partial target state.
        tx.commit().unwrap();
        result
    }

    fn ledger(&self, conn: &Connection) -> LedgerState {
        read_with_keys_sync(conn, &self.key, Some(&self.keys), self.identity)
            .unwrap()
            .unwrap()
    }

    fn checkpoint(&self, conn: &Connection) -> AuditCheckpoint {
        let ledger = self.ledger(conn);
        let chain = ledger.continuity.as_ref().unwrap();
        let checkpoint = AuditCheckpoint::issue(
            &self.keys,
            CheckpointBody {
                version: 1,
                identity: self.identity,
                sequence: ledger.sequence,
                root_anchor: ledger.terminal,
                anchor: chain.terminal,
                epoch_at_sequence: chain.active_epoch,
                signing_epoch: chain.active_epoch,
                acknowledged_export: [0; 32],
            },
        )
        .unwrap();
        self.apply(conn, AuditCommand::Checkpoint(checkpoint.clone()), 100)
            .unwrap();
        checkpoint
    }

    fn activate(&self, conn: &Connection) -> PreparedTargetMutation {
        let event = self.event(1);
        let checkpoint = self.ledger(conn).continuity.unwrap().checkpoint.unwrap();
        let profile = row(conn, "config_netconf_profile", "singleton", 1);
        let effect = TargetEffectV1 {
            format: 1,
            authority: self.identity,
            profile_incarnation: [0x51; 16],
            device_incarnation: [0x52; 16],
            caller: event.caller,
            request: event.request,
            action: 0.try_into().unwrap(),
            destination: TargetExpectationV1::Lifecycle {
                state_digest: serde_json::from_value(profile["state_digest"].clone()).unwrap(),
            },
            source: None,
            lock: None,
            expires_at: 160,
            encrypted_payload: None,
            resolution: Some(TargetResolutionV1::Activate { checkpoint }),
        };
        self.prepare(effect, event)
    }

    fn prepare(
        &self,
        effect: TargetEffectV1,
        event: ProjectedAuditEvent,
    ) -> PreparedTargetMutation {
        let binding =
            AuditOperationBinding::project(&self.privacy, &event, 0, b"target-state").unwrap();
        let mutation = authenticate(
            &self.key,
            b"openpacketcore/management-audit/netconf-target/v1\0",
            &effect,
        )
        .unwrap();
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: self.identity,
                binding,
                event,
                issued_at: 100,
                expires_at: effect.expires_at,
                nonce: [0x53; 16],
                key_epoch: self.key.epoch(),
                mutation: Some(mutation),
            },
            &self.key,
        )
        .unwrap();
        PreparedTargetMutation { handle, effect }
    }
}

fn row(conn: &Connection, table: &str, column: &str, slot: u8) -> Value {
    let bytes: Vec<u8> = conn
        .query_row(
            &format!("SELECT state_json FROM {table} WHERE {column}=?1"),
            [slot],
            |row| row.get(0),
        )
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn target_state_activation_retains_the_exact_audit_anchor_and_tombstones() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let prepared = fixture.activate(&conn);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(prepared.clone()))),
            100,
        )
        .unwrap();
    fixture.checkpoint(&conn);
    let applied = fixture.apply(
        &conn,
        AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(prepared.clone()))),
        100,
    );
    assert!(
        applied.is_ok(),
        "checkpointed target activation did not apply"
    );
    let ledger = fixture.ledger(&conn);
    let receipt = ledger
        .lookup(&fixture.key, prepared.handle(), prepared.effect.caller)
        .unwrap()
        .unwrap();
    let AuditOperationState::TargetV1(result) = receipt.state() else {
        panic!("activation has no typed retained result");
    };
    assert!(matches!(
        result.outcome(),
        NetconfAppliedOutcome::Lifecycle { .. }
    ));
    assert!(!receipt.terminal_recorded());
    let profile = row(&conn, "config_netconf_profile", "singleton", 1);
    assert_eq!(
        profile["state_digest"],
        serde_json::to_value(result.state_digest()).unwrap()
    );
    assert_eq!(profile["last_target_transition_sequence"], receipt.sequence);
    assert!(!profile["activation_operation"].is_null());
    assert!(!profile["bootstrap_checkpoint"].is_null());
    for target in [0, 1] {
        let state = row(&conn, "config_netconf_targets", "target", target);
        assert_eq!(state["generation"], 0);
        assert_eq!(state["present"], false);
    }
    drop(conn);
    let reopened = Connection::open(fixture.directory.path().join("authority.sqlite")).unwrap();
    assert_eq!(
        row(&reopened, "config_netconf_profile", "singleton", 1),
        profile
    );
    assert_eq!(
        fixture
            .ledger(&reopened)
            .lookup(&fixture.key, prepared.handle(), prepared.effect.caller)
            .unwrap()
            .unwrap()
            .state(),
        receipt.state()
    );
}

impl Fixture {
    fn submit(&self, conn: &Connection, prepared: &PreparedTargetMutation) -> AuditOperationState {
        self.apply(
            conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(prepared.clone()))),
            100,
        )
        .unwrap();
        self.checkpoint(conn);
        let _ = self.apply(
            conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(prepared.clone()))),
            100,
        );
        self.ledger(conn)
            .lookup(&self.key, prepared.handle(), prepared.effect.caller)
            .unwrap()
            .unwrap()
            .state()
    }

    fn settle(&self, conn: &Connection, prepared: &PreparedTargetMutation) {
        self.apply(conn, AuditCommand::Terminal(prepared.handle.clone()), 100)
            .unwrap();
        self.checkpoint(conn);
    }

    fn active(&self, conn: &Connection) {
        let prepared = self.activate(conn);
        assert!(matches!(
            self.submit(conn, &prepared),
            AuditOperationState::TargetV1(_)
        ));
        self.settle(conn, &prepared);
    }

    fn request(
        &self,
        conn: &Connection,
        request: u8,
        action: u8,
        session: u8,
        slot: u8,
    ) -> PreparedTargetMutation {
        use crate::consensus::audit_mutation::TargetLockExpectationV1;
        let event = self.event(request);
        let profile = row(conn, "config_netconf_profile", "singleton", 1);
        let lifecycle = row(conn, "config_netconf_lifecycle", "singleton", 1);
        let destination = if matches!(action, 4 | 5) {
            TargetExpectationV1::Candidate {
                generation: crate::CandidateGeneration {
                    authority: self.identity,
                    value: row(conn, "config_netconf_targets", "target", 0)["generation"]
                        .as_u64()
                        .unwrap(),
                },
            }
        } else if matches!(action, 7 | 8) {
            TargetExpectationV1::Startup {
                revision: crate::StartupRevision {
                    authority: self.identity,
                    value: row(conn, "config_netconf_targets", "target", 1)["generation"]
                        .as_u64()
                        .unwrap(),
                },
            }
        } else {
            TargetExpectationV1::Lifecycle {
                state_digest: serde_json::from_value(profile["state_digest"].clone()).unwrap(),
            }
        };
        let lock = if matches!(action, 2..=8) {
            Some(TargetLockExpectationV1 {
                datastore: slot,
                incarnation: lifecycle["locks"][usize::from(slot)]["incarnation"]
                    .as_u64()
                    .unwrap(),
                session: serde_json::from_value(
                    lifecycle["locks"][usize::from(slot)]["session"].clone(),
                )
                .unwrap(),
                requester: [session; 16],
            })
        } else {
            None
        };
        let resolution = match action {
            1 => Some(TargetResolutionV1::BeginDevice {
                previous: serde_json::from_value(profile["device_incarnation"].clone()).unwrap(),
            }),
            2 => Some(TargetResolutionV1::AcquireLock {
                session: [session; 16],
            }),
            3 => Some(TargetResolutionV1::ReleaseLock {
                session: [session; 16],
            }),
            13 => Some(TargetResolutionV1::EndSession {
                session: [session; 16],
            }),
            _ => None,
        };
        self.prepare(
            TargetEffectV1 {
                format: 1,
                authority: self.identity,
                profile_incarnation: [0x51; 16],
                device_incarnation: if action == 1 {
                    [request; 16]
                } else {
                    serde_json::from_value(profile["device_incarnation"].clone()).unwrap()
                },
                caller: event.caller,
                request: event.request,
                action: action.try_into().unwrap(),
                destination,
                source: None,
                lock,
                expires_at: 160,
                encrypted_payload: None,
                resolution,
            },
            event,
        )
    }

    fn encrypted(&self, mut prepared: PreparedTargetMutation, seed: u8) -> PreparedTargetMutation {
        use crate::consensus::audit_mutation::{TargetEncryptedBlobV1, TargetPayloadV1};
        use opc_crypto::encrypt_attested_envelope_with_handle_and_nonce;
        use opc_key::{
            ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, AES_256_GCM_SIV_KEY_LEN,
            AES_256_GCM_SIV_NONCE_LEN,
        };
        use sha2::{Digest, Sha256};
        let (target, version) = match prepared.effect.destination {
            TargetExpectationV1::Candidate { generation } => (0, generation.get() + 1),
            TargetExpectationV1::Startup { revision } => (1, revision.get() + 1),
            _ => panic!("target fixture required"),
        };
        let schema = opc_types::SchemaDigest::from_bytes([0x71; 32]);
        let aad = EnvelopeAad::config(
            opc_types::TenantId::from_static("fixture-tenant"),
            version,
            ConfigAad::new(
                opc_types::TxId::new(),
                None,
                opc_types::Timestamp::now_utc(),
                "fixture-principal",
                schema,
                prepared
                    .effect
                    .encryption_store_kind(schema, target)
                    .unwrap(),
            )
            .unwrap(),
        );
        let key = KeyHandle::new(
            KeyId::new("fixture-target-key").unwrap(),
            KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([seed; AES_256_GCM_SIV_KEY_LEN]),
        );
        let envelope = encrypt_attested_envelope_with_handle_and_nonce(
            &key,
            &aad,
            &[0x72; 32],
            [seed; AES_256_GCM_SIV_NONCE_LEN],
        )
        .unwrap();
        prepared.effect.encrypted_payload = Some(TargetPayloadV1::Target(TargetEncryptedBlobV1 {
            schema,
            plaintext_digest: Sha256::digest([0x72; 32]).into(),
            encrypted_blob: envelope.encoded().to_vec(),
        }));
        self.prepare(prepared.effect, prepared.handle.body.event)
    }
}

fn target_rows(conn: &Connection) -> Vec<(String, u8, Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    for (table, column, slots) in [
        ("config_netconf_profile", "singleton", vec![1]),
        ("config_netconf_targets", "target", vec![0, 1]),
        ("config_netconf_lifecycle", "singleton", vec![1]),
    ] {
        for slot in slots {
            let (body, mac): (Vec<u8>, Vec<u8>) = conn
                .query_row(
                    &format!("SELECT state_json,state_hmac FROM {table} WHERE {column}=?1"),
                    [slot],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            result.push((table.to_owned(), slot, body, mac));
        }
    }
    result
}

fn restore_rows(conn: &Connection, rows: &[(String, u8, Vec<u8>, Vec<u8>)]) {
    for (table, slot, body, mac) in rows {
        let column = if table == "config_netconf_targets" {
            "target"
        } else {
            "singleton"
        };
        conn.execute(
            &format!("UPDATE {table} SET state_json=?1,state_hmac=?2 WHERE {column}=?3"),
            params![body, mac, slot],
        )
        .unwrap();
    }
}

#[tokio::test]
async fn target_state_requires_original_checkpoint_and_retains_rejections_and_terminal_debt() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let activation = fixture.activate(&conn);
    let before = target_rows(&conn);
    let apply =
        || AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(activation.clone())));
    assert!(fixture.apply(&conn, apply(), 100).is_err());
    assert_eq!(target_rows(&conn), before);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(activation.clone()))),
            100,
        )
        .unwrap();
    assert!(fixture.apply(&conn, apply(), 100).is_err());
    assert_eq!(target_rows(&conn), before);
    assert_eq!(
        fixture
            .ledger(&conn)
            .lookup(&fixture.key, activation.handle(), activation.effect.caller)
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Intent
    );
    fixture.checkpoint(&conn);
    fixture.apply(&conn, apply(), 100).unwrap();
    let discard = fixture.request(&conn, 2, 5, 0x61, 1);
    let active = target_rows(&conn);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(discard.clone()))),
            100,
        )
        .unwrap();
    fixture.checkpoint(&conn);
    assert!(fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(discard.clone()))),
            100
        )
        .is_err());
    assert_eq!(
        target_rows(&conn),
        active,
        "terminal debt allowed a target effect"
    );
    fixture.settle(&conn, &activation);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(discard.clone()))),
            200,
        )
        .unwrap_err();
    assert_eq!(target_rows(&conn), active);
    assert_eq!(
        fixture
            .ledger(&conn)
            .lookup(&fixture.key, discard.handle(), discard.effect.caller)
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Rejected
    );
    fixture.settle(&conn, &discard);
    // Known activation remains truthful after expiry and subsequent rejection.
    fixture.apply(&conn, apply(), 200).unwrap();
    assert_eq!(target_rows(&conn), active);
}

#[tokio::test]
async fn target_state_generations_locks_and_session_loss_fence_stale_effects() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let stage = fixture.encrypted(fixture.request(&conn, 2, 4, 0x61, 1), 0x73);
    let AuditOperationState::TargetV1(result) = fixture.submit(&conn, &stage) else {
        panic!("stage refused");
    };
    assert!(
        matches!(result.outcome(), NetconfAppliedOutcome::Candidate { generation } if generation.get() == 1)
    );
    fixture.settle(&conn, &stage);
    let original_candidate = row(&conn, "config_netconf_targets", "target", 0);
    let late_stage = fixture.encrypted(fixture.request(&conn, 3, 4, 0x61, 1), 0x74);
    let acquire = fixture.request(&conn, 4, 2, 0x61, 1);
    assert!(matches!(
        fixture.submit(&conn, &acquire),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &acquire);
    let before = target_rows(&conn);
    assert_eq!(
        fixture.submit(&conn, &late_stage),
        AuditOperationState::Rejected,
        "stale lock observation applied"
    );
    assert_eq!(target_rows(&conn), before);
    fixture.settle(&conn, &late_stage);
    let foreign = fixture.request(&conn, 5, 5, 0x62, 1);
    assert_eq!(
        fixture.submit(&conn, &foreign),
        AuditOperationState::Rejected
    );
    assert_eq!(target_rows(&conn), before);
    fixture.settle(&conn, &foreign);
    let startup = fixture.encrypted(fixture.request(&conn, 6, 7, 0x61, 2), 0x75);
    assert!(
        matches!(fixture.submit(&conn, &startup), AuditOperationState::TargetV1(result) if matches!(result.outcome(), NetconfAppliedOutcome::Startup { revision } if revision.get() == 1))
    );
    fixture.settle(&conn, &startup);
    assert_eq!(
        row(&conn, "config_netconf_targets", "target", 0),
        original_candidate
    );
    let retained_startup = row(&conn, "config_netconf_targets", "target", 1);
    let release = fixture.request(&conn, 7, 3, 0x61, 1);
    assert!(matches!(
        fixture.submit(&conn, &release),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &release);
    let retired = row(&conn, "config_netconf_targets", "target", 0);
    assert_eq!(retired["generation"], 2);
    assert_eq!(retired["present"], false);
    assert_eq!(
        row(&conn, "config_netconf_targets", "target", 1),
        retained_startup
    );
    let late_unlocked = fixture.encrypted(fixture.request(&conn, 8, 7, 0x61, 2), 0x76);
    let end = fixture.request(&conn, 9, 13, 0x61, 0);
    assert!(matches!(
        fixture.submit(&conn, &end),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &end);
    let before = target_rows(&conn);
    assert_eq!(
        fixture.submit(&conn, &late_unlocked),
        AuditOperationState::Rejected,
        "closed session retained an unlocked prepared effect"
    );
    assert_eq!(target_rows(&conn), before);
    fixture.settle(&conn, &late_unlocked);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(stage.clone()))),
            200,
        )
        .unwrap();
    assert_eq!(
        target_rows(&conn),
        before,
        "known request replay repeated its effect"
    );
    assert_eq!(
        row(&conn, "config_netconf_targets", "target", 1),
        retained_startup
    );
    crate::consensus::audit_targets::validate_inactive_sync(
        &conn,
        &fixture.key,
        fixture.identity,
        &crate::consensus::sqlite::SqliteWorkCancellation::new(),
    )
    .unwrap();
}

#[tokio::test]
async fn target_state_pruned_anchor_rejects_authenticated_older_rows_and_snapshot_validation() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let old = target_rows(&conn);
    let discard = fixture.request(&conn, 2, 5, 0x61, 1);
    assert!(matches!(
        fixture.submit(&conn, &discard),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &discard);
    let current = target_rows(&conn);
    let ledger = fixture.ledger(&conn);
    let mut body = ledger
        .continuity
        .as_ref()
        .unwrap()
        .checkpoint
        .as_ref()
        .unwrap()
        .body
        .clone();
    // This fixture is the signing authority, recording an export acknowledgement
    // for the exact already-checkpointed prefix. It tests retained state/pruning,
    // not a recipient-only export capability.
    body.acknowledged_export = [0x77; 32];
    let export = AuditCheckpoint::issue(&fixture.keys, body).unwrap();
    fixture
        .apply(&conn, AuditCommand::AcknowledgeExport(export.clone()), 200)
        .unwrap();
    fixture
        .apply(
            &conn,
            AuditCommand::Prune {
                through: ledger.sequence,
                checkpoint: export,
            },
            200,
        )
        .unwrap();
    assert!(fixture.ledger(&conn).entries.is_empty());
    let validate = || {
        crate::consensus::audit_targets::validate_inactive_sync(
            &conn,
            &fixture.key,
            fixture.identity,
            &crate::consensus::sqlite::SqliteWorkCancellation::new(),
        )
    };
    validate().unwrap();
    restore_rows(&conn, &old);
    assert!(
        validate().is_err(),
        "authenticated target rollback survived ledger prefix pruning"
    );
    restore_rows(&conn, &current);
    validate().unwrap();
}
