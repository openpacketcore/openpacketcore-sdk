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
                generation: crate::audit_authority::CandidateGeneration {
                    authority: self.identity,
                    value: row(conn, "config_netconf_targets", "target", 0)["generation"]
                        .as_u64()
                        .unwrap(),
                },
            }
        } else if matches!(action, 7 | 8) {
            TargetExpectationV1::Startup {
                revision: crate::audit_authority::StartupRevision {
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
    let owed = serde_json::to_vec(&fixture.ledger(&conn)).unwrap();
    assert!(
        fixture
            .apply(
                &conn,
                AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(discard.clone()))),
                100,
            )
            .is_err(),
        "terminal debt admitted a later target intent"
    );
    assert_eq!(serde_json::to_vec(&fixture.ledger(&conn)).unwrap(), owed);
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
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(discard.clone()))),
            100,
        )
        .unwrap();
    fixture.checkpoint(&conn);
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
        &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
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
            &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
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

#[tokio::test]
async fn target_state_result_must_match_the_retained_action_profile_and_successor() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let discard = fixture.request(&conn, 2, 5, 0x61, 1);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(discard.clone()))),
            100,
        )
        .unwrap();
    fixture.checkpoint(&conn);
    let admitted = fixture.ledger(&conn);
    let AuditOperationState::TargetV1(correct) = fixture.submit(&conn, &discard) else {
        panic!("discard refused");
    };
    use crate::audit_authority::{CandidateGeneration, NetconfTargetResult, StartupRevision};
    let wrong = [
        NetconfTargetResult::new(
            fixture.identity,
            [0x7e; 16],
            correct.state_digest(),
            correct.outcome(),
        )
        .unwrap(),
        NetconfTargetResult::new(
            fixture.identity,
            correct.profile_incarnation(),
            correct.state_digest(),
            NetconfAppliedOutcome::Startup {
                revision: StartupRevision {
                    authority: fixture.identity,
                    value: 1,
                },
            },
        )
        .unwrap(),
        NetconfTargetResult::new(
            fixture.identity,
            correct.profile_incarnation(),
            correct.state_digest(),
            NetconfAppliedOutcome::Candidate {
                generation: CandidateGeneration {
                    authority: fixture.identity,
                    value: 2,
                },
            },
        )
        .unwrap(),
    ];
    for result in wrong {
        let mut trial = admitted.clone();
        let unchanged = serde_json::to_vec(&trial).unwrap();
        assert!(
            trial
                .resolve(
                    &fixture.key,
                    discard.handle(),
                    AuditOperationState::TargetV1(result)
                )
                .is_err(),
            "mismatched retained target result accepted"
        );
        assert_eq!(
            serde_json::to_vec(&trial).unwrap(),
            unchanged,
            "refused result changed the ledger"
        );
    }
    let mut positive = admitted;
    positive
        .resolve(
            &fixture.key,
            discard.handle(),
            AuditOperationState::TargetV1(correct),
        )
        .unwrap();
    positive.seal_continuity(Some(&fixture.keys)).unwrap();
    positive.validate(&fixture.key, fixture.identity).unwrap();
    positive.validate_continuity(Some(&fixture.keys)).unwrap();
}

#[tokio::test]
async fn target_state_reconstruction_rejects_authentic_but_substituted_result() {
    use crate::audit_authority::ledger::{verify, EntryPayload, TargetStateAnchor};
    const ENTRY_DOMAIN: &[u8] = b"openpacketcore/management-audit/replicated-entry/v1\0";
    use crate::audit_authority::{NetconfTargetResult, StartupRevision};
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let discard = fixture.request(&conn, 2, 5, 0x61, 1);
    let AuditOperationState::TargetV1(correct) = fixture.submit(&conn, &discard) else {
        panic!("discard refused");
    };
    let valid = fixture.ledger(&conn);
    valid.validate(&fixture.key, fixture.identity).unwrap();
    let wrong = NetconfTargetResult::new(
        fixture.identity,
        correct.profile_incarnation(),
        correct.state_digest(),
        NetconfAppliedOutcome::Startup {
            revision: StartupRevision {
                authority: fixture.identity,
                value: 1,
            },
        },
    )
    .unwrap();
    let mut substituted = valid.clone();
    let op = substituted
        .operations
        .iter_mut()
        .find(|op| op.handle == discard.handle)
        .unwrap();
    op.state = AuditOperationState::TargetV1(wrong);
    substituted.target_anchor = Some(TargetStateAnchor {
        sequence: op.last_sequence,
        result: wrong,
    });
    for entry in &mut substituted.entries {
        if let EntryPayload::Outcome { operation, state } = &mut entry.payload {
            if *operation == discard.handle.mac {
                *state = AuditOperationState::TargetV1(wrong);
            }
        }
    }
    // Model an authority-side outcome substitution, not a bad-MAC shortcut.
    // Root ledger validation must bind the genuine stored result to its intent.
    let mut previous = substituted.predecessor;
    for entry in &mut substituted.entries {
        entry.previous = previous;
        entry.mac = authenticate(
            &fixture.key,
            ENTRY_DOMAIN,
            &(
                fixture.identity,
                entry.sequence,
                previous,
                entry.key_epoch,
                &entry.payload,
            ),
        )
        .unwrap();
        verify(
            &fixture.key,
            ENTRY_DOMAIN,
            &(
                fixture.identity,
                entry.sequence,
                previous,
                entry.key_epoch,
                &entry.payload,
            ),
            &entry.mac,
        )
        .unwrap();
        previous = entry.mac;
    }
    substituted.terminal = previous;
    assert!(
        substituted
            .validate(&fixture.key, fixture.identity)
            .is_err(),
        "authenticated substituted target result survived reconstruction"
    );
    // The actual stored operation and target rows were not touched.
    assert_eq!(
        serde_json::to_vec(&fixture.ledger(&conn)).unwrap(),
        serde_json::to_vec(&valid).unwrap()
    );
}

impl Fixture {
    fn running_target(
        &self,
        conn: &Connection,
        request: u8,
        action: u8,
        source_slot: u8,
        source_seed: u8,
    ) -> PreparedTargetMutation {
        use crate::consensus::audit_mutation::{
            TargetEncryptedBlobV1, TargetLockExpectationV1, TargetPayloadV1, TargetSourceV1,
        };
        use opc_crypto::{
            decrypt_envelope_with_handle, encrypt_attested_envelope_with_handle_and_nonce,
        };
        use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose};
        use sha2::{Digest, Sha256};
        let source = row(conn, "config_netconf_targets", "target", source_slot);
        let blob: TargetEncryptedBlobV1 =
            serde_json::from_value(source["encrypted_envelope"].clone()).unwrap();
        let source_key = KeyHandle::new(
            KeyId::new("fixture-target-key").unwrap(),
            KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([source_seed; 32]),
        );
        let envelope = opc_crypto::CryptoEnvelopeRef::decode(&blob.encrypted_blob).unwrap();
        let (source_aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
        let plaintext =
            decrypt_envelope_with_handle(&source_key, &source_aad, &blob.encrypted_blob).unwrap();
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&plaintext)),
            blob.plaintext_digest
        );
        let base: u64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version),0) FROM config_history",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let parent = if base == 0 {
            None
        } else {
            let bytes: Vec<u8> = conn
                .query_row(
                    "SELECT tx_id FROM config_history ORDER BY version DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            Some(opc_types::TxId::from_uuid(
                uuid::Uuid::from_slice(&bytes).unwrap(),
            ))
        };
        let tx_id = opc_types::TxId::new();
        let committed_at = "2026-01-01T00:00:00Z"
            .parse::<opc_types::Timestamp>()
            .unwrap();
        let principal = r#"{"tenant":"fixture-tenant","subject":"fixture-principal"}"#.to_owned();
        let aad = EnvelopeAad::config(
            opc_types::TenantId::from_static("fixture-tenant"),
            base + 1,
            ConfigAad::new(
                tx_id,
                parent,
                committed_at,
                &principal,
                blob.schema,
                "running",
            )
            .unwrap(),
        );
        let destination_key = KeyHandle::new(
            KeyId::new("fixture-running-key").unwrap(),
            KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([0x7b; 32]),
        );
        let destination = encrypt_attested_envelope_with_handle_and_nonce(
            &destination_key,
            &aad,
            &plaintext,
            [request; 12],
        )
        .unwrap();
        let commit = crate::consensus::PreparedConfigCommit::prepare(
            crate::CommitRecord {
                tx_id,
                parent_tx_id: parent,
                version: opc_types::ConfigVersion::new(base + 1),
                committed_at,
                principal,
                source: crate::CommitSource::Netconf,
                schema_digest: blob.schema,
                plaintext_digest: blob.plaintext_digest.to_vec(),
                encrypted_blob: destination.encoded().to_vec(),
                rollback_point: false,
                confirmed_deadline: None,
            },
            Vec::new(),
            &self.key,
        )
        .unwrap();
        let generation = source["generation"].as_u64().unwrap();
        let ciphertext_digest = Sha256::digest(&blob.encrypted_blob).into();
        let source = if source_slot == 0 {
            TargetSourceV1::Candidate {
                generation: crate::audit_authority::CandidateGeneration {
                    authority: self.identity,
                    value: generation,
                },
                schema: blob.schema,
                ciphertext_digest,
            }
        } else {
            TargetSourceV1::Startup {
                revision: crate::audit_authority::StartupRevision {
                    authority: self.identity,
                    value: generation,
                },
                schema: blob.schema,
                ciphertext_digest,
            }
        };
        let mut prepared = self.request(conn, request, 6, 0x61, 0);
        prepared.effect.action = action.try_into().unwrap();
        prepared.effect.destination = TargetExpectationV1::Running { version: base };
        prepared.effect.source = Some(source);
        prepared.effect.encrypted_payload = Some(TargetPayloadV1::Running {
            commit: Box::new(commit),
            confirmation_ownership: None,
        });
        let lifecycle = row(conn, "config_netconf_lifecycle", "singleton", 1);
        prepared.effect.lock = Some(TargetLockExpectationV1 {
            datastore: 0,
            incarnation: lifecycle["locks"][0]["incarnation"].as_u64().unwrap(),
            session: serde_json::from_value(lifecycle["locks"][0]["session"].clone()).unwrap(),
            requester: [0x61; 16],
        });
        // Reissue only within this synthetic SDK fixture, binding the exact observed base.
        let mut prepared = self.prepare(prepared.effect, prepared.handle.body.event);
        prepared.handle.body.binding.base_version = base;
        prepared.handle = AuditOperationHandle::issue(prepared.handle.body, &self.key).unwrap();
        prepared.verify_effect(&self.key).unwrap();
        prepared
    }

    fn assert_running_plaintext(&self, conn: &Connection, expected: &PreparedTargetMutation) {
        use crate::consensus::audit_mutation::TargetPayloadV1;
        let Some(TargetPayloadV1::Running { commit, .. }) = &expected.effect.encrypted_payload
        else {
            panic!("running fixture");
        };
        let (version, bytes): (u64, Vec<u8>) = conn
            .query_row(
                "SELECT version,encrypted_blob FROM config_history ORDER BY version DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(version, commit.record.version.get());
        assert_eq!(bytes, commit.record.encrypted_blob);
        let key = opc_key::KeyHandle::new(
            opc_key::KeyId::new("fixture-running-key").unwrap(),
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([0x7b; 32]),
        );
        let envelope = opc_crypto::CryptoEnvelopeRef::decode(&bytes).unwrap();
        let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
        assert_eq!(
            *opc_crypto::decrypt_envelope_with_handle(&key, &aad, &bytes).unwrap(),
            vec![0x72; 32]
        );
        crate::consensus::history::validate_record_chain_sync(
            conn,
            &self.key,
            &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
        )
        .unwrap();
    }
}

#[tokio::test]
async fn target_running_promotion_atomically_retires_the_exact_candidate() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let stage = fixture.encrypted(fixture.request(&conn, 81, 4, 0x61, 1), 0x31);
    assert!(matches!(
        fixture.submit(&conn, &stage),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &stage);
    let prepared = fixture.running_target(&conn, 82, 6, 0, 0x31);
    let result = fixture.submit(&conn, &prepared);
    assert!(
        matches!(result, AuditOperationState::TargetV1(result)
        if matches!(result.outcome(), NetconfAppliedOutcome::Promoted { running_version: 1, retired_generation } if retired_generation.get() == 2)),
        "checkpointed candidate promotion did not atomically apply"
    );
    fixture.assert_running_plaintext(&conn, &prepared);
    let candidate = row(&conn, "config_netconf_targets", "target", 0);
    assert_eq!(candidate["generation"], 2);
    assert_eq!(candidate["present"], false);
    let before = target_rows(&conn);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(prepared.clone()))),
            200,
        )
        .unwrap();
    assert_eq!(
        target_rows(&conn),
        before,
        "known promotion must not retire again after expiry"
    );
    assert_eq!(
        fixture
            .ledger(&conn)
            .lookup(&fixture.key, prepared.handle(), prepared.effect.caller)
            .unwrap()
            .unwrap()
            .state(),
        result
    );
    fixture.settle(&conn, &prepared);
}

#[tokio::test]
async fn target_running_copy_preserves_candidate_and_startup_sources() {
    for source_slot in [0, 1] {
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        fixture.active(&conn);
        let stage = fixture.encrypted(
            fixture.request(
                &conn,
                83,
                if source_slot == 0 { 4 } else { 7 },
                0x61,
                source_slot + 1,
            ),
            0x32,
        );
        assert!(matches!(
            fixture.submit(&conn, &stage),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &stage);
        let source_before = row(&conn, "config_netconf_targets", "target", source_slot);
        let prepared = fixture.running_target(&conn, 84, 15, source_slot, 0x32);
        assert!(
            matches!(fixture.submit(&conn, &prepared), AuditOperationState::TargetV1(result)
            if matches!(result.outcome(), NetconfAppliedOutcome::CopiedRunning { running_version: 1 })),
            "checkpointed target copy did not apply to running"
        );
        fixture.assert_running_plaintext(&conn, &prepared);
        assert_eq!(
            row(&conn, "config_netconf_targets", "target", source_slot),
            source_before,
            "copy must preserve its source generation and ciphertext"
        );
        fixture.settle(&conn, &prepared);
    }
}

#[tokio::test]
async fn target_running_copy_rejects_replaced_source_without_any_effect() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let stage = fixture.encrypted(fixture.request(&conn, 85, 4, 0x61, 1), 0x33);
    assert!(matches!(
        fixture.submit(&conn, &stage),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &stage);
    let old_copy = fixture.running_target(&conn, 86, 15, 0, 0x33);
    let replacement = fixture.encrypted(fixture.request(&conn, 87, 4, 0x61, 1), 0x34);
    assert!(matches!(
        fixture.submit(&conn, &replacement),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &replacement);
    let before = target_rows(&conn);
    assert_eq!(
        fixture.submit(&conn, &old_copy),
        AuditOperationState::Rejected,
        "copy accepted a substituted source generation and ciphertext"
    );
    assert_eq!(target_rows(&conn), before);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM config_history", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    let receipt = fixture
        .ledger(&conn)
        .lookup(&fixture.key, old_copy.handle(), old_copy.effect.caller)
        .unwrap()
        .unwrap();
    assert!(
        !receipt.terminal_recorded(),
        "retained rejection keeps its original terminal obligation"
    );
    fixture.settle(&conn, &old_copy);
    let current_copy = fixture.running_target(&conn, 88, 15, 0, 0x34);
    assert!(matches!(
        fixture.submit(&conn, &current_copy),
        AuditOperationState::TargetV1(_)
    ));
    fixture.assert_running_plaintext(&conn, &current_copy);
    assert_eq!(
        row(&conn, "config_netconf_targets", "target", 0)["generation"],
        2
    );
}

#[tokio::test]
async fn target_running_promotion_rolls_back_running_and_retirement_on_storage_failure() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let stage = fixture.encrypted(fixture.request(&conn, 89, 4, 0x61, 1), 0x35);
    assert!(matches!(
        fixture.submit(&conn, &stage),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &stage);
    let prepared = fixture.running_target(&conn, 90, 6, 0, 0x35);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(prepared.clone()))),
            100,
        )
        .unwrap();
    fixture.checkpoint(&conn);
    let before = target_rows(&conn);
    let ledger_before = serde_json::to_vec(&fixture.ledger(&conn)).unwrap();
    // Synthetic last-row I/O fault after running append and earlier target writes.
    conn.execute_batch("CREATE TEMP TRIGGER fail_target_lifecycle BEFORE UPDATE ON config_netconf_lifecycle BEGIN SELECT RAISE(ABORT, 'synthetic target write failure'); END;").unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    assert!(
        apply_sync(
            &tx,
            &fixture.key,
            fixture.identity,
            &AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(prepared.clone()))),
            100,
            Some(&fixture.keys)
        )
        .is_err(),
        "injected storage failure must abort the authority transaction"
    );
    drop(tx);
    conn.execute_batch("DROP TRIGGER fail_target_lifecycle")
        .unwrap();
    assert_eq!(target_rows(&conn), before);
    assert_eq!(
        serde_json::to_vec(&fixture.ledger(&conn)).unwrap(),
        ledger_before
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM config_history", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    crate::consensus::history::validate_record_chain_sync(
        &conn,
        &fixture.key,
        &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
    )
    .unwrap();
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(prepared.clone()))),
            100,
        )
        .unwrap();
    fixture.assert_running_plaintext(&conn, &prepared);
    assert_eq!(
        row(&conn, "config_netconf_targets", "target", 0)["generation"],
        2
    );
    fixture.settle(&conn, &prepared);
}

impl Fixture {
    fn bind_current_base(
        &self,
        conn: &Connection,
        mut prepared: PreparedTargetMutation,
    ) -> PreparedTargetMutation {
        let base: u64 = conn
            .query_row(
                "SELECT COALESCE(MAX(version),0) FROM config_history",
                [],
                |r| r.get(0),
            )
            .unwrap();
        prepared.handle.body.binding.base_version = base;
        prepared.handle = AuditOperationHandle::issue(prepared.handle.body, &self.key).unwrap();
        prepared.verify_effect(&self.key).unwrap();
        prepared
    }

    fn tentative_target(
        &self,
        conn: &Connection,
        request: u8,
        source_seed: u8,
    ) -> PreparedTargetMutation {
        use crate::consensus::audit_mutation::{TargetEncryptedBlobV1, TargetPayloadV1};
        use opc_crypto::encrypt_attested_envelope_with_handle_and_nonce;
        use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose};
        use sha2::{Digest, Sha256};
        let mut prepared = self.running_target(conn, request, 6, 0, source_seed);
        prepared.effect.action = 9.try_into().unwrap();
        let Some(TargetPayloadV1::Running { commit, .. }) = &mut prepared.effect.encrypted_payload
        else {
            panic!("running fixture");
        };
        let pending = crate::audit_authority::NetconfPendingConfirmation {
            authority: self.identity,
            value: [request; 16],
        };
        let deadline = commit.record.committed_at.add_seconds(60).unwrap();
        commit.record.confirmed_deadline = Some(deadline);
        let schema = commit.record.schema_digest;
        let version = commit.record.version.get();
        prepared.effect.resolution = Some(TargetResolutionV1::InstallPending {
            pending,
            rollback_parent: commit.record.parent_tx_id.unwrap(),
            rollback_version: prepared.handle.body.binding.base_version,
            original_deadline: deadline.as_offset_datetime().unix_timestamp(),
            owner_session: [0x61; 16],
            persistent: true,
        });
        // The reviewed ownership domain uses the same bounded pre-encryption
        // binding as target envelopes, with the fixed confirmation target tag.
        // Spell it independently so this detector does not require a new API.
        let effect = &prepared.effect;
        let binding = serde_json::to_vec(&(
            effect.format,
            effect.authority,
            effect.profile_incarnation,
            effect.device_incarnation,
            effect.caller,
            effect.request,
            effect.action,
            &effect.destination,
            &effect.source,
            &effect.lock,
            effect.expires_at,
            &effect.resolution,
            schema,
            2_u8,
        ))
        .unwrap();
        let mut hash = Sha256::new();
        hash.update(b"openpacketcore/config-netconf/target-aad/v1\0");
        hash.update(binding);
        use std::fmt::Write;
        let mut domain = "netconf-confirmation-v1-".to_owned();
        for byte in hash.finalize() {
            write!(&mut domain, "{byte:02x}").unwrap();
        }
        let aad = EnvelopeAad::config(
            opc_types::TenantId::from_static("fixture-tenant"),
            version,
            ConfigAad::new(
                opc_types::TxId::new(),
                None,
                "2026-01-01T00:00:00Z".parse().unwrap(),
                "fixture-principal",
                schema,
                domain,
            )
            .unwrap(),
        );
        let key = KeyHandle::new(
            KeyId::new("fixture-confirmation-key").unwrap(),
            KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([0x79; 32]),
        );
        let ownership = encrypt_attested_envelope_with_handle_and_nonce(
            &key,
            &aad,
            b"synthetic-confirmation-owner",
            [request; 12],
        )
        .unwrap();
        let Some(TargetPayloadV1::Running {
            confirmation_ownership,
            ..
        }) = &mut prepared.effect.encrypted_payload
        else {
            panic!("running fixture");
        };
        *confirmation_ownership = Some(TargetEncryptedBlobV1 {
            schema,
            plaintext_digest: Sha256::digest(b"synthetic-confirmation-owner").into(),
            encrypted_blob: ownership.encoded().to_vec(),
        });
        let prepared = self.prepare(prepared.effect, prepared.handle.body.event);
        self.bind_current_base(conn, prepared)
    }
}

#[tokio::test]
async fn target_confirmation_tentative_retains_exact_rollback_deadline_and_encrypted_ownership() {
    use crate::consensus::audit_mutation::TargetPayloadV1;
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let initial = fixture.encrypted(fixture.request(&conn, 91, 4, 0x61, 1), 0x36);
    assert!(matches!(
        fixture.submit(&conn, &initial),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &initial);
    let running = fixture.running_target(&conn, 92, 6, 0, 0x36);
    assert!(matches!(
        fixture.submit(&conn, &running),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &running);
    let staged = fixture.encrypted(fixture.request(&conn, 93, 4, 0x61, 1), 0x37);
    let staged = fixture.bind_current_base(&conn, staged);
    assert!(matches!(
        fixture.submit(&conn, &staged),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &staged);
    let prepared = fixture.tentative_target(&conn, 94, 0x37);
    let Some(TargetResolutionV1::InstallPending {
        pending,
        rollback_parent,
        rollback_version,
        original_deadline,
        owner_session,
        persistent,
    }) = prepared.effect.resolution
    else {
        panic!("pending fixture");
    };
    let Some(TargetPayloadV1::Running {
        commit,
        confirmation_ownership: Some(ownership),
    }) = &prepared.effect.encrypted_payload
    else {
        panic!("ownership fixture");
    };
    let result = fixture.submit(&conn, &prepared);
    assert!(
        matches!(result, AuditOperationState::TargetV1(result)
        if matches!(result.outcome(), NetconfAppliedOutcome::Tentative { running_version: 2, retired_generation, pending: observed }
            if retired_generation.get() == 4 && observed == pending)),
        "checkpointed tentative promotion did not retain its ownership atomically"
    );
    fixture.assert_running_plaintext(&conn, &prepared);
    let candidate = row(&conn, "config_netconf_targets", "target", 0);
    assert_eq!(candidate["generation"], 4);
    assert_eq!(candidate["present"], false);
    let lifecycle = row(&conn, "config_netconf_lifecycle", "singleton", 1);
    let retained = &lifecycle["pending_confirmation"];
    assert_eq!(retained["pending"], serde_json::to_value(pending).unwrap());
    assert_eq!(
        retained["tx_id"],
        serde_json::to_value(commit.record.tx_id).unwrap()
    );
    assert_eq!(retained["running_version"], 2);
    assert_eq!(
        retained["owner_session"],
        serde_json::to_value(owner_session).unwrap()
    );
    assert_eq!(retained["persistent"], persistent);
    assert_eq!(
        lifecycle["rollback_parent"]["tx_id"],
        serde_json::to_value(rollback_parent).unwrap()
    );
    assert_eq!(lifecycle["rollback_parent"]["version"], rollback_version);
    assert_eq!(lifecycle["original_deadline"], original_deadline);
    assert_eq!(
        lifecycle["encrypted_confirmation_ownership"],
        serde_json::to_value(ownership).unwrap()
    );
    let before = target_rows(&conn);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(prepared.clone()))),
            200,
        )
        .unwrap();
    assert_eq!(
        target_rows(&conn),
        before,
        "known replay cannot extend the pending deadline"
    );
    fixture.settle(&conn, &prepared);
}

impl Fixture {
    fn rebind_at(
        &self,
        conn: &Connection,
        mut prepared: PreparedTargetMutation,
        now: i64,
    ) -> PreparedTargetMutation {
        prepared.effect.expires_at = now + 60;
        prepared.handle.body.expires_at = now + 60;
        prepared.handle.body.issued_at = now;
        prepared.handle.body.mutation = Some(
            authenticate(
                &self.key,
                b"openpacketcore/management-audit/netconf-target/v1\0",
                &prepared.effect,
            )
            .unwrap(),
        );
        self.bind_current_base(conn, prepared)
    }

    fn submit_at(
        &self,
        conn: &Connection,
        prepared: &PreparedTargetMutation,
        now: i64,
    ) -> AuditOperationState {
        self.apply(
            conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(prepared.clone()))),
            now,
        )
        .unwrap();
        self.checkpoint(conn);
        let _ = self.apply(
            conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(prepared.clone()))),
            now,
        );
        self.ledger(conn)
            .lookup(&self.key, prepared.handle(), prepared.effect.caller)
            .unwrap()
            .unwrap()
            .state()
    }

    fn pending_fixture(&self, conn: &Connection, persistent: bool) -> PreparedTargetMutation {
        use crate::consensus::audit_mutation::TargetPayloadV1;
        use opc_crypto::encrypt_attested_envelope_with_handle_and_nonce;
        use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose};
        use sha2::{Digest, Sha256};
        self.active(conn);
        let initial = self.encrypted(self.request(conn, 101, 4, 0x61, 1), 0x36);
        assert!(matches!(
            self.submit(conn, &initial),
            AuditOperationState::TargetV1(_)
        ));
        self.settle(conn, &initial);
        let first = self.running_target(conn, 102, 6, 0, 0x36);
        assert!(matches!(
            self.submit(conn, &first),
            AuditOperationState::TargetV1(_)
        ));
        self.settle(conn, &first);
        let mut staged = self.encrypted(self.request(conn, 103, 4, 0x61, 1), 0x37);
        let Some(TargetPayloadV1::Target(blob)) = &mut staged.effect.encrypted_payload else {
            panic!("staged fixture");
        };
        let envelope = opc_crypto::CryptoEnvelopeRef::decode(&blob.encrypted_blob).unwrap();
        let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
        let key = KeyHandle::new(
            KeyId::new("fixture-target-key").unwrap(),
            KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([0x37; 32]),
        );
        blob.encrypted_blob =
            encrypt_attested_envelope_with_handle_and_nonce(&key, &aad, &[0x73; 32], [0x38; 12])
                .unwrap()
                .encoded()
                .to_vec();
        blob.plaintext_digest = Sha256::digest([0x73; 32]).into();
        let staged = self.rebind_at(conn, staged, 100);
        assert!(matches!(
            self.submit(conn, &staged),
            AuditOperationState::TargetV1(_)
        ));
        self.settle(conn, &staged);
        let mut tentative = self.tentative_target(conn, 104, 0x37);
        let Some(TargetResolutionV1::InstallPending {
            persistent: supplied,
            ..
        }) = &mut tentative.effect.resolution
        else {
            panic!("pending fixture");
        };
        *supplied = persistent;
        let Some(TargetPayloadV1::Running { commit, .. }) = &tentative.effect.encrypted_payload
        else {
            panic!("running fixture");
        };
        let schema = commit.record.schema_digest;
        let aad = EnvelopeAad::config(
            opc_types::TenantId::from_static("fixture-tenant"),
            commit.record.version.get(),
            ConfigAad::new(
                opc_types::TxId::new(),
                None,
                commit.record.committed_at,
                "fixture-principal",
                schema,
                tentative.effect.encryption_store_kind(schema, 2).unwrap(),
            )
            .unwrap(),
        );
        let key = KeyHandle::new(
            KeyId::new("fixture-confirmation-key").unwrap(),
            KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([0x79; 32]),
        );
        let Some(TargetPayloadV1::Running {
            confirmation_ownership: Some(blob),
            ..
        }) = &mut tentative.effect.encrypted_payload
        else {
            panic!("ownership fixture");
        };
        blob.encrypted_blob = encrypt_attested_envelope_with_handle_and_nonce(
            &key,
            &aad,
            b"synthetic-confirmation-owner",
            [105; 12],
        )
        .unwrap()
        .encoded()
        .to_vec();
        self.rebind_at(conn, tentative, 100)
    }

    fn resolve_fixture(
        &self,
        conn: &Connection,
        request: u8,
        action: u8,
        internal: bool,
        now: i64,
    ) -> PreparedTargetMutation {
        use crate::consensus::audit_mutation::{
            TargetLockExpectationV1, TargetPayloadV1, TargetSourceV1,
        };
        use opc_crypto::{
            decrypt_envelope_with_handle, encrypt_attested_envelope_with_handle_and_nonce,
        };
        use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose};
        let lifecycle = row(conn, "config_netconf_lifecycle", "singleton", 1);
        let pending = &lifecycle["pending_confirmation"];
        let token = serde_json::from_value(pending["pending"].clone()).unwrap();
        let deadline = lifecycle["original_deadline"].as_i64().unwrap();
        let mut prepared = self.request(conn, request, 10, 0x61, 0);
        prepared.effect.action = action.try_into().unwrap();
        prepared.effect.lock = Some(TargetLockExpectationV1 {
            datastore: 0,
            incarnation: lifecycle["locks"][0]["incarnation"].as_u64().unwrap(),
            session: serde_json::from_value(lifecycle["locks"][0]["session"].clone()).unwrap(),
            requester: [0x61; 16],
        });
        prepared.effect.resolution = if action == 14 {
            Some(TargetResolutionV1::RebootRecovery {
                previous_device: serde_json::from_value(pending["device_incarnation"].clone())
                    .unwrap(),
                pending: Some(token),
                original_deadline: Some(deadline),
            })
        } else {
            Some(TargetResolutionV1::ResolvePending {
                pending: token,
                original_deadline: deadline,
            })
        };
        if internal {
            prepared.handle.body.event.transport = ManagementAuditTransportCode::Internal;
        }
        if action != 10 {
            let parent = &lifecycle["rollback_parent"];
            let parent_tx: opc_types::TxId =
                serde_json::from_value(parent["tx_id"].clone()).unwrap();
            let encrypted: Vec<u8> = conn
                .query_row(
                    "SELECT encrypted_blob FROM config_history WHERE tx_id=?1",
                    [parent_tx.as_uuid().as_bytes().as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            let key = KeyHandle::new(
                KeyId::new("fixture-running-key").unwrap(),
                KeyPurpose::Config,
                opc_types::TenantId::from_static("fixture-tenant"),
                zeroize::Zeroizing::new([0x7b; 32]),
            );
            let envelope = opc_crypto::CryptoEnvelopeRef::decode(&encrypted).unwrap();
            let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
            let plaintext = decrypt_envelope_with_handle(&key, &aad, &encrypted).unwrap();
            assert_eq!(
                plaintext.as_slice(),
                &[0x72; 32],
                "rollback source must be original, not tentative plaintext"
            );
            let pending_tx: opc_types::TxId =
                serde_json::from_value(pending["tx_id"].clone()).unwrap();
            let version = pending["running_version"].as_u64().unwrap();
            let tx_id = opc_types::TxId::new();
            let committed_at = opc_types::Timestamp::from_offset_datetime(
                time::OffsetDateTime::from_unix_timestamp(now).unwrap(),
            );
            let schema = serde_json::from_value(parent["schema"].clone()).unwrap();
            let principal =
                r#"{"tenant":"fixture-tenant","subject":"fixture-principal"}"#.to_owned();
            let aad = EnvelopeAad::config(
                opc_types::TenantId::from_static("fixture-tenant"),
                version + 1,
                ConfigAad::new(
                    tx_id,
                    Some(pending_tx),
                    committed_at,
                    &principal,
                    schema,
                    "running",
                )
                .unwrap(),
            );
            let encrypted = encrypt_attested_envelope_with_handle_and_nonce(
                &key,
                &aad,
                &plaintext,
                [request; 12],
            )
            .unwrap();
            let commit = crate::consensus::PreparedConfigCommit::prepare(
                crate::CommitRecord {
                    tx_id,
                    parent_tx_id: Some(pending_tx),
                    version: opc_types::ConfigVersion::new(version + 1),
                    committed_at,
                    principal,
                    source: crate::CommitSource::CommitConfirmedRestore,
                    schema_digest: schema,
                    plaintext_digest: serde_json::from_value::<Vec<u8>>(
                        parent["plaintext_digest"].clone(),
                    )
                    .unwrap(),
                    encrypted_blob: encrypted.encoded().to_vec(),
                    rollback_point: false,
                    confirmed_deadline: None,
                },
                Vec::new(),
                &self.key,
            )
            .unwrap();
            prepared.effect.destination = TargetExpectationV1::Running { version };
            prepared.effect.source = Some(TargetSourceV1::Running {
                version: parent["version"].as_u64().unwrap(),
                schema,
                ciphertext_digest: serde_json::from_value(parent["ciphertext_digest"].clone())
                    .unwrap(),
            });
            prepared.effect.encrypted_payload = Some(TargetPayloadV1::Running {
                commit: Box::new(commit),
                confirmation_ownership: None,
            });
        }
        self.rebind_at(conn, prepared, now)
    }

    fn assert_no_pending(&self, conn: &Connection) {
        let lifecycle = row(conn, "config_netconf_lifecycle", "singleton", 1);
        for field in [
            "pending_confirmation",
            "rollback_parent",
            "original_deadline",
            "encrypted_confirmation_ownership",
        ] {
            assert!(
                lifecycle[field].is_null(),
                "pending field retained after resolution"
            );
        }
        assert_eq!(lifecycle["cleanup"], serde_json::json!([null, null, null]));
        crate::consensus::history::validate_record_chain_sync(
            conn,
            &self.key,
            &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
        )
        .unwrap();
        crate::consensus::audit_targets::validate_inactive_sync(
            conn,
            &self.key,
            self.identity,
            &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
        )
        .unwrap();
    }
}

#[tokio::test]
async fn target_confirmation_rejects_substituted_ownership_aad_before_any_effect() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let original = fixture.pending_fixture(&conn, false);
    let mut altered = original.clone();
    let Some(TargetResolutionV1::InstallPending { persistent, .. }) =
        &mut altered.effect.resolution
    else {
        panic!("fixture");
    };
    *persistent = true; // Valid AEAD still binds the nonpersistent ownership.
    let altered = fixture.rebind_at(&conn, altered, 100);
    let before = target_rows(&conn);
    assert_eq!(
        fixture.submit(&conn, &altered),
        AuditOperationState::Rejected,
        "ownership from another pending binding was accepted"
    );
    assert_eq!(target_rows(&conn), before);
    assert_eq!(
        conn.query_row("SELECT MAX(version) FROM config_history", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        1
    );
    fixture.settle(&conn, &altered);
}

#[tokio::test]
async fn target_confirmation_exact_confirm_rejects_wrong_pending_deadline_and_session() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let tentative = fixture.pending_fixture(&conn, false);
    assert!(matches!(
        fixture.submit(&conn, &tentative),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &tentative);
    for (id, variant) in [(110, 0), (111, 1), (112, 2)] {
        let mut wrong = fixture.resolve_fixture(&conn, id, 10, false, 100);
        match variant {
            0 => {
                let Some(TargetResolutionV1::ResolvePending { pending, .. }) =
                    &mut wrong.effect.resolution
                else {
                    panic!("fixture");
                };
                pending.value = [0xf1; 16];
            }
            1 => {
                let Some(TargetResolutionV1::ResolvePending {
                    original_deadline, ..
                }) = &mut wrong.effect.resolution
                else {
                    panic!("fixture");
                };
                *original_deadline += 1;
            }
            _ => wrong.effect.lock.as_mut().unwrap().requester = [0xf2; 16],
        }
        let wrong = fixture.rebind_at(&conn, wrong, 100);
        let before = target_rows(&conn);
        assert_eq!(
            fixture.submit(&conn, &wrong),
            AuditOperationState::Rejected,
            "confirmation ignored its exact pending ownership"
        );
        assert_eq!(target_rows(&conn), before);
        fixture.settle(&conn, &wrong);
    }
    let exact = fixture.resolve_fixture(&conn, 113, 10, false, 100);
    assert!(
        matches!(fixture.submit(&conn,&exact),AuditOperationState::TargetV1(r) if matches!(r.outcome(),NetconfAppliedOutcome::Confirmed{..}))
    );
    fixture.assert_no_pending(&conn);
    let confirmed: Option<String> = conn
        .query_row(
            "SELECT confirmed_at FROM config_history ORDER BY version DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(confirmed.is_some());
    let before = target_rows(&conn);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(exact.clone()))),
            200,
        )
        .unwrap();
    assert_eq!(target_rows(&conn), before);
    fixture.settle(&conn, &exact);
}

#[tokio::test]
async fn target_confirmation_cancel_restores_the_original_encrypted_parent() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let tentative = fixture.pending_fixture(&conn, true);
    assert!(matches!(
        fixture.submit(&conn, &tentative),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &tentative);
    let exact = fixture.resolve_fixture(&conn, 114, 11, false, 100);
    assert!(
        matches!(fixture.submit(&conn,&exact),AuditOperationState::TargetV1(r) if matches!(r.outcome(),NetconfAppliedOutcome::RolledBack{running_version:3,..}))
    );
    fixture.assert_running_plaintext(&conn, &exact);
    fixture.assert_no_pending(&conn);
    fixture.settle(&conn, &exact);
}

#[tokio::test]
async fn target_confirmation_expiry_preserves_original_deadline_and_rejects_early_or_late_confirmation(
) {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let tentative = fixture.pending_fixture(&conn, true);
    assert!(matches!(
        fixture.submit(&conn, &tentative),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &tentative);
    let deadline = row(&conn, "config_netconf_lifecycle", "singleton", 1)["original_deadline"]
        .as_i64()
        .unwrap();
    for (id, action, internal, now) in [(115, 12, true, deadline - 1), (116, 10, false, deadline)] {
        let wrong = fixture.resolve_fixture(&conn, id, action, internal, now);
        let before = target_rows(&conn);
        assert_eq!(
            fixture.submit_at(&conn, &wrong, now),
            AuditOperationState::Rejected,
            "original deadline did not fence resolution"
        );
        assert_eq!(target_rows(&conn), before);
        fixture.settle(&conn, &wrong);
    }
    let exact = fixture.resolve_fixture(&conn, 117, 12, true, deadline);
    assert!(
        matches!(fixture.submit_at(&conn,&exact,deadline),AuditOperationState::TargetV1(r) if matches!(r.outcome(),NetconfAppliedOutcome::RolledBack{running_version:3,..}))
    );
    fixture.assert_running_plaintext(&conn, &exact);
    fixture.assert_no_pending(&conn);
    fixture.settle(&conn, &exact);
}

#[tokio::test]
async fn target_confirmation_session_loss_distinguishes_persistent_ownership() {
    for persistent in [false, true] {
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        let tentative = fixture.pending_fixture(&conn, persistent);
        assert!(matches!(
            fixture.submit(&conn, &tentative),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &tentative);
        let end = fixture.request(&conn, 118, 13, 0x61, 0);
        let end = fixture.rebind_at(&conn, end, 100);
        assert!(matches!(
            fixture.submit(&conn, &end),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &end);
        let lifecycle = row(&conn, "config_netconf_lifecycle", "singleton", 1);
        assert_eq!(lifecycle["cleanup"][0].is_null(), persistent);
        let exact = fixture.resolve_fixture(
            &conn,
            119,
            if persistent { 10 } else { 11 },
            !persistent,
            100,
        );
        assert!(matches!(
            fixture.submit(&conn, &exact),
            AuditOperationState::TargetV1(_)
        ));
        if !persistent {
            fixture.assert_running_plaintext(&conn, &exact);
        }
        fixture.assert_no_pending(&conn);
        fixture.settle(&conn, &exact);
    }
}

#[tokio::test]
async fn target_confirmation_reopen_preserves_pending_and_device_reboot_requires_exact_rollback() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let tentative = fixture.pending_fixture(&conn, true);
    assert!(matches!(
        fixture.submit(&conn, &tentative),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &tentative);
    let before = target_rows(&conn);
    drop(conn);
    let conn = Connection::open(fixture.directory.path().join("authority.sqlite")).unwrap();
    crate::consensus::audit_targets::validate_inactive_sync(
        &conn,
        &fixture.key,
        fixture.identity,
        &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
    )
    .unwrap();
    assert_eq!(target_rows(&conn), before);
    let begin = fixture.request(&conn, 120, 1, 0x61, 0);
    let begin = fixture.rebind_at(&conn, begin, 100);
    assert!(matches!(
        fixture.submit(&conn, &begin),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &begin);
    assert!(!row(&conn, "config_netconf_lifecycle", "singleton", 1)["cleanup"][0].is_null());
    let wrong = fixture.resolve_fixture(&conn, 121, 10, false, 100);
    let before = target_rows(&conn);
    assert_eq!(fixture.submit(&conn, &wrong), AuditOperationState::Rejected);
    assert_eq!(target_rows(&conn), before);
    fixture.settle(&conn, &wrong);
    let exact = fixture.resolve_fixture(&conn, 122, 14, true, 100);
    assert!(
        matches!(fixture.submit(&conn,&exact),AuditOperationState::TargetV1(r) if matches!(r.outcome(),NetconfAppliedOutcome::RolledBack{running_version:3,..}))
    );
    fixture.assert_running_plaintext(&conn, &exact);
    fixture.assert_no_pending(&conn);
    fixture.settle(&conn, &exact);
}
impl Fixture {
    fn fallback_copy(&self, conn: &Connection, request: u8) -> PreparedTargetMutation {
        use crate::consensus::audit_mutation::{TargetPayloadV1, TargetSourceV1};
        use opc_crypto::{
            decrypt_envelope_with_handle, encrypt_attested_envelope_with_handle_and_nonce,
        };
        use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose};
        use sha2::{Digest, Sha256};
        let candidate = row(conn, "config_netconf_targets", "target", 0);
        assert_eq!(candidate["present"], false);
        let (version, tx, encrypted): (u64, Vec<u8>, Vec<u8>) = conn.query_row(
            "SELECT version,tx_id,encrypted_blob FROM config_history ORDER BY version DESC LIMIT 1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        let key = KeyHandle::new(
            KeyId::new("fixture-running-key").unwrap(),
            KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([0x7b; 32]),
        );
        let envelope = opc_crypto::CryptoEnvelopeRef::decode(&encrypted).unwrap();
        let (source_aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
        let plaintext = decrypt_envelope_with_handle(&key, &source_aad, &encrypted).unwrap();
        let opc_key::EnvelopeMetadata::Config(metadata) = source_aad.metadata() else {
            panic!("running source");
        };
        let schema = *metadata.schema_digest();
        let parent = opc_types::TxId::from_uuid(uuid::Uuid::from_slice(&tx).unwrap());
        let tx_id = opc_types::TxId::new();
        let committed_at = "2026-01-01T00:00:00Z"
            .parse::<opc_types::Timestamp>()
            .unwrap();
        let principal = r#"{"tenant":"fixture-tenant","subject":"fixture-principal"}"#.to_owned();
        let aad = EnvelopeAad::config(
            opc_types::TenantId::from_static("fixture-tenant"),
            version + 1,
            ConfigAad::new(
                tx_id,
                Some(parent),
                committed_at,
                &principal,
                schema,
                "running",
            )
            .unwrap(),
        );
        let destination =
            encrypt_attested_envelope_with_handle_and_nonce(&key, &aad, &plaintext, [request; 12])
                .unwrap();
        let commit = crate::consensus::PreparedConfigCommit::prepare(
            crate::CommitRecord {
                tx_id,
                parent_tx_id: Some(parent),
                version: opc_types::ConfigVersion::new(version + 1),
                committed_at,
                principal,
                source: crate::CommitSource::Netconf,
                schema_digest: schema,
                plaintext_digest: Sha256::digest(&plaintext).to_vec(),
                encrypted_blob: destination.encoded().to_vec(),
                rollback_point: false,
                confirmed_deadline: None,
            },
            Vec::new(),
            &self.key,
        )
        .unwrap();
        let mut prepared = self.request(conn, request, 6, 0x61, 0);
        prepared.effect.action = 15.try_into().unwrap();
        prepared.effect.destination = TargetExpectationV1::Running { version };
        prepared.effect.source = Some(TargetSourceV1::CandidateFallback {
            generation: crate::audit_authority::CandidateGeneration {
                authority: self.identity,
                value: candidate["generation"].as_u64().unwrap(),
            },
            running_version: version,
            schema,
            ciphertext_digest: Sha256::digest(encrypted).into(),
        });
        prepared.effect.encrypted_payload = Some(TargetPayloadV1::Running {
            commit: Box::new(commit),
            confirmation_ownership: None,
        });
        self.rebind_at(conn, prepared, 100)
    }
}

#[tokio::test]
async fn target_fallback_copy_binds_the_absent_candidate_and_exact_running_source() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let staged = fixture.encrypted(fixture.request(&conn, 131, 4, 0x61, 1), 0x39);
    assert!(matches!(
        fixture.submit(&conn, &staged),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &staged);
    let running = fixture.running_target(&conn, 132, 6, 0, 0x39);
    assert!(matches!(
        fixture.submit(&conn, &running),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &running);
    let candidate = row(&conn, "config_netconf_targets", "target", 0);
    let copy = fixture.fallback_copy(&conn, 133);
    assert!(
        matches!(fixture.submit(&conn,&copy),AuditOperationState::TargetV1(r) if matches!(r.outcome(),NetconfAppliedOutcome::CopiedRunning{running_version:2})),
        "checkpointed absent-candidate fallback copy did not apply"
    );
    fixture.assert_running_plaintext(&conn, &copy);
    assert_eq!(
        row(&conn, "config_netconf_targets", "target", 0),
        candidate,
        "fallback copy modified its source tombstone"
    );
    fixture.settle(&conn, &copy);
    let old = fixture.fallback_copy(&conn, 134);
    let discard = fixture.request(&conn, 135, 5, 0x61, 1);
    let discard = fixture.rebind_at(&conn, discard, 100);
    assert!(matches!(
        fixture.submit(&conn, &discard),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &discard);
    let before = target_rows(&conn);
    assert_eq!(
        fixture.submit(&conn, &old),
        AuditOperationState::Rejected,
        "fallback copy accepted a substituted absent generation"
    );
    assert_eq!(target_rows(&conn), before);
    fixture.settle(&conn, &old);
    let fresh = fixture.fallback_copy(&conn, 136);
    assert!(
        matches!(fixture.submit(&conn,&fresh),AuditOperationState::TargetV1(r) if matches!(r.outcome(),NetconfAppliedOutcome::CopiedRunning{running_version:3}))
    );
    fixture.assert_running_plaintext(&conn, &fresh);
    fixture.settle(&conn, &fresh);
}

// The target contract must reject unknown nested input even when a reused
// legacy codec historically ignored it. No authority key or MAC is changed.
fn assert_closed_target_input(prepared: &PreparedTargetMutation, paths: &[&str]) {
    let encoded = prepared.encode().unwrap();
    assert_eq!(PreparedTargetMutation::decode(&encoded).unwrap(), *prepared);
    for phase in [false, true] {
        let command = AuditCommand::NetconfTarget(Box::new(if phase {
            TargetAuditCommandV1::Apply(prepared.clone())
        } else {
            TargetAuditCommandV1::Admit(prepared.clone())
        }));
        let bytes = opc_consensus::encode_bounded(&command).unwrap();
        let restored: AuditCommand = opc_consensus::decode_bounded(&bytes).unwrap();
        assert_eq!(
            serde_json::to_value(&restored).unwrap(),
            serde_json::to_value(&command).unwrap()
        );
        assert_eq!(opc_consensus::encode_bounded(&restored).unwrap(), bytes);
    }
    for path in paths {
        let mut value = serde_json::to_value(prepared).unwrap();
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("unallocated-target-field".into(), serde_json::json!(0));
        assert!(
            PreparedTargetMutation::decode(&serde_json::to_vec(&value).unwrap()).is_err(),
            "target recovery accepted unknown nested input"
        );
        for phase in ["admit", "apply"] {
            let command = serde_json::json!({"netconf-target": {phase: value.clone()}});
            assert!(
                serde_json::from_value::<AuditCommand>(command).is_err(),
                "target command accepted unknown nested input"
            );
        }
    }
}

#[tokio::test]
async fn target_closed_input_rejects_unknown_bootstrap_checkpoint_identity() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let prepared = fixture.activate(&conn);
    assert_closed_target_input(
        &prepared,
        &[
            "/effect/resolution/activate/checkpoint/body/identity",
            "/effect/resolution/activate/checkpoint/body",
            "/effect/resolution/activate/checkpoint",
        ],
    );
}

#[tokio::test]
async fn target_closed_input_rejects_unknown_running_commit_and_audit_fields() {
    use crate::consensus::audit_mutation::TargetPayloadV1;
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let stage = fixture.encrypted(fixture.request(&conn, 141, 4, 0x61, 1), 0x41);
    assert!(matches!(
        fixture.submit(&conn, &stage),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &stage);
    let mut prepared = fixture.running_target(&conn, 142, 6, 0, 0x41);
    let Some(TargetPayloadV1::Running { commit, .. }) = &mut prepared.effect.encrypted_payload
    else {
        panic!("running fixture");
    };
    let audit = crate::AuditRecord {
        tx_id: commit.record.tx_id,
        sequence: 0,
        yang_path: "/fixture:configuration".into(),
        op_type: crate::AuditOpType::Replace,
        previous_value: None,
        new_value: None,
        redaction_applied: false,
        previous_hash: [0; 32],
        entry_hmac: [0; 32],
    };
    **commit = crate::consensus::PreparedConfigCommit::prepare(
        commit.record.clone(),
        vec![audit],
        &fixture.key,
    )
    .unwrap();
    let prepared = fixture.rebind_at(&conn, prepared, 100);
    prepared.verify_effect(&fixture.key).unwrap();
    assert_closed_target_input(
        &prepared,
        &[
            "/effect/encrypted_payload/running/commit",
            "/effect/encrypted_payload/running/commit/record",
            "/effect/encrypted_payload/running/commit/audit/0",
        ],
    );
}

use crate::audit_authority::AuditOperationReceipt;

impl Fixture {
    fn preflight(
        &self,
        conn: &Connection,
        prepared: &PreparedTargetMutation,
        now: i64,
    ) -> Result<Option<AuditOperationReceipt>, AuditAuthorityError> {
        let before = target_rows(conn);
        let audit_before = serde_json::to_vec(&self.ledger(conn)).unwrap();
        let changes: i64 = conn
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        let ledger = self.ledger(&tx);
        let result = crate::consensus::audit_targets::preflight_target_sync(
            &tx,
            &self.key,
            prepared,
            &ledger,
            &self.keys,
            now,
            &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
        )
        .unwrap();
        tx.commit().unwrap();
        let after: i64 = conn
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(after, changes, "preflight executed a SQL write");
        assert_eq!(target_rows(conn), before);
        assert_eq!(
            serde_json::to_vec(&self.ledger(conn)).unwrap(),
            audit_before
        );
        result
    }
}

#[tokio::test]
async fn target_sdk_preflight_predicts_current_transition_without_admission_or_effect() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let activation = fixture.activate(&conn);
    assert_eq!(fixture.preflight(&conn, &activation, 100).unwrap(), None);
    assert!(matches!(
        fixture.submit(&conn, &activation),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &activation);
    let staged = fixture.encrypted(fixture.request(&conn, 150, 4, 0x61, 1), 0x39);
    assert_eq!(fixture.preflight(&conn, &staged, 100).unwrap(), None);
    assert!(matches!(
        fixture.submit(&conn, &staged),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &staged);
    let running = fixture.running_target(&conn, 151, 6, 0, 0x39);
    assert_eq!(fixture.preflight(&conn, &running, 100).unwrap(), None);
    assert!(matches!(
        fixture.submit(&conn, &running),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &running);
    fixture.assert_running_plaintext(&conn, &running);
}

#[tokio::test]
async fn target_sdk_preflight_refuses_stale_generation_source_lock_and_expiry() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let delayed = fixture.encrypted(fixture.request(&conn, 152, 4, 0x61, 1), 0x39);
    let first = fixture.encrypted(fixture.request(&conn, 153, 4, 0x61, 1), 0x3a);
    assert!(matches!(
        fixture.submit(&conn, &first),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &first);
    assert_eq!(
        fixture.preflight(&conn, &delayed, 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
    let copied = fixture.running_target(&conn, 154, 15, 0, 0x3a);
    assert_eq!(fixture.preflight(&conn, &copied, 100).unwrap(), None);
    let replacement = fixture.encrypted(fixture.request(&conn, 155, 4, 0x61, 1), 0x3b);
    assert!(matches!(
        fixture.submit(&conn, &replacement),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &replacement);
    assert_eq!(
        fixture.preflight(&conn, &copied, 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
    let delayed = fixture.request(&conn, 156, 5, 0x61, 1);
    let acquired = fixture.request(&conn, 157, 2, 0x61, 1);
    assert_eq!(fixture.preflight(&conn, &acquired, 100).unwrap(), None);
    assert!(matches!(
        fixture.submit(&conn, &acquired),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &acquired);
    assert_eq!(
        fixture.preflight(&conn, &delayed, 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
    let foreign = fixture.request(&conn, 158, 5, 0x62, 1);
    assert_eq!(
        fixture.preflight(&conn, &foreign, 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
    let fresh = fixture.request(&conn, 159, 5, 0x61, 1);
    assert_eq!(fixture.preflight(&conn, &fresh, 100).unwrap(), None);
    assert_eq!(
        fixture.preflight(&conn, &fresh, 160),
        Err(AuditAuthorityError::Expired)
    );
    // A second request with an identical intent body is still not a receipt.
    assert!(fixture
        .ledger(&conn)
        .lookup(&fixture.key, fresh.handle(), fresh.effect.caller)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn target_sdk_preflight_preserves_original_receipts_and_fences_unresolved_work() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let original = fixture.encrypted(fixture.request(&conn, 160, 4, 0x61, 1), 0x3c);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(original.clone()))),
            100,
        )
        .unwrap();
    let receipt = fixture.preflight(&conn, &original, 200).unwrap().unwrap();
    assert_eq!(receipt.state(), AuditOperationState::Intent);
    assert_eq!(
        fixture
            .ledger(&conn)
            .recover_target(&fixture.key, original.handle(), original.effect.caller)
            .unwrap(),
        original
    );
    let next = fixture.request(&conn, 161, 5, 0x61, 1);
    assert_eq!(
        fixture.preflight(&conn, &next, 100),
        Err(AuditAuthorityError::RecoveryRequired)
    );
    fixture.checkpoint(&conn);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(original.clone()))),
            100,
        )
        .unwrap();
    let known = fixture.preflight(&conn, &original, 200).unwrap().unwrap();
    assert!(matches!(known.state(), AuditOperationState::TargetV1(_)));
    assert!(!known.terminal_recorded());
    let next = fixture.request(&conn, 161, 5, 0x61, 1);
    assert_eq!(
        fixture.preflight(&conn, &next, 100),
        Err(AuditAuthorityError::RecoveryRequired)
    );
    fixture.settle(&conn, &original);
    assert_eq!(fixture.preflight(&conn, &next, 100).unwrap(), None);
    assert!(matches!(
        fixture.submit(&conn, &next),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &next);
    let replay = fixture.preflight(&conn, &original, 200).unwrap().unwrap();
    assert_eq!(replay.state(), known.state());
    assert!(replay.terminal_recorded());
    // A newly signed, conflicting use of the original request does not inherit
    // its retained receipt or replace its exact recovery description.
    let collision = fixture.encrypted(fixture.request(&conn, 160, 4, 0x61, 1), 0x3d);
    assert_eq!(
        fixture.preflight(&conn, &collision, 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
    let wrong = fixture.request(&conn, 162, 5, 0x61, 1);
    fixture
        .apply(&conn, AuditCommand::Intent(wrong.handle.clone()), 100)
        .unwrap();
    assert_eq!(
        fixture.preflight(&conn, &wrong, 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
}

impl Fixture {
    fn device_view(&self, conn: &Connection) -> crate::consensus::audit_targets::NetconfDeviceView {
        let tx = conn.unchecked_transaction().unwrap();
        let view = crate::consensus::audit_targets::read_device_view_sync(
            &tx,
            &self.key,
            &self.ledger(&tx),
            &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
        )
        .unwrap();
        tx.commit().unwrap();
        view
    }

    fn device_event(&self, request: u8) -> ProjectedAuditEvent {
        let event = ManagementAuditEventRecord::try_new(
            [request; 16],
            ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
                .unwrap(),
            "fixture-tenant",
            "fixture-principal",
            ManagementAuditTransportCode::Internal,
            ManagementAuditOperationCode::Exec,
            ManagementAuditOutcomeCode::Intent,
            None::<&str>,
            ["/fixture:lifecycle"],
            None::<&str>,
        )
        .unwrap();
        ProjectedAuditEvent::project(&self.privacy, &event).unwrap()
    }
}

#[tokio::test]
async fn target_device_preparation_binds_activation_then_exact_previous_device() {
    use crate::audit_authority::{NetconfDeviceOwner, NetconfWorkerBinding, PreparedNetconfDevice};
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let view = fixture.device_view(&conn);
    let before = target_rows(&conn);
    let event = fixture.device_event(170);
    let effect = view.prepare(&event, 160, [0x51; 16], [0x52; 16]).unwrap();
    assert_eq!(u8::from(effect.action), 0);
    assert_eq!(effect.expires_at, 160);
    let activation = fixture.prepare(effect, event.clone());
    assert_eq!(target_rows(&conn), before);
    assert_eq!(
        activation.effect.digest(&fixture.key).unwrap(),
        activation.handle.body.mutation.unwrap()
    );
    assert_eq!(fixture.preflight(&conn, &activation, 100).unwrap(), None);
    let worker = std::sync::Arc::new(());
    let prepared = PreparedNetconfDevice {
        worker: NetconfWorkerBinding::new(&worker),
        prepared: activation.clone(),
    };
    assert_eq!(prepared.mutation(), &activation);
    let owner = NetconfDeviceOwner {
        worker: prepared.worker.clone(),
        authority: fixture.identity,
        profile_incarnation: [0x51; 16],
        device_incarnation: [0x52; 16],
        caller: event.caller,
    };
    assert_eq!(
        view.verify_owner(&owner),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert!(matches!(
        fixture.submit(&conn, &activation),
        AuditOperationState::TargetV1(_)
    ));
    assert_eq!(
        fixture.device_view(&conn).verify_owner(&owner),
        Err(AuditAuthorityError::RecoveryRequired)
    );
    fixture.settle(&conn, &activation);
    assert_eq!(fixture.device_view(&conn).verify_owner(&owner), Ok(()));
    let next_event = fixture.device_event(171);
    let next = fixture
        .device_view(&conn)
        .prepare(&next_event, 160, [0x53; 16], [0x54; 16])
        .unwrap();
    assert_eq!(u8::from(next.action), 1);
    assert_eq!(next.profile_incarnation, [0x51; 16]);
    assert!(
        matches!(next.resolution, Some(TargetResolutionV1::BeginDevice { previous: Some(value) }) if value == [0x52;16])
    );
    let next = fixture.prepare(next, next_event);
    assert_eq!(fixture.preflight(&conn, &next, 100).unwrap(), None);
    assert!(matches!(
        fixture.submit(&conn, &next),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &next);
    assert_eq!(
        fixture.device_view(&conn).verify_owner(&owner),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert_eq!(
        format!("{owner:?} {prepared:?}"),
        "NetconfDeviceOwner(<redacted>) PreparedNetconfDevice(<redacted>)"
    );
}

#[tokio::test]
async fn target_device_preparation_refuses_rpc_events_unsettled_and_reused_incarnations() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let view = fixture.device_view(&conn);
    assert!(matches!(
        view.prepare(&fixture.event(172), 160, [0x51; 16], [0x52; 16]),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    let event = fixture.device_event(173);
    let prepared = fixture.prepare(
        view.prepare(&event, 160, [0x51; 16], [0x52; 16]).unwrap(),
        event,
    );
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(prepared.clone()))),
            100,
        )
        .unwrap();
    let view = fixture.device_view(&conn);
    assert!(matches!(
        view.prepare(&fixture.device_event(174), 160, [0x55; 16], [0x56; 16]),
        Err(AuditAuthorityError::RecoveryRequired)
    ));
    fixture.checkpoint(&conn);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(prepared.clone()))),
            100,
        )
        .unwrap();
    fixture.settle(&conn, &prepared);
    let view = fixture.device_view(&conn);
    assert!(matches!(
        view.prepare(&fixture.device_event(174), 160, [0x55; 16], [0x52; 16]),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert!(matches!(
        view.prepare(&fixture.device_event(174), 160, [0; 16], [0x56; 16]),
        Err(AuditAuthorityError::BindingMismatch)
    ));
}

#[test]
fn target_device_worker_binding_rejects_equal_value_replacement_and_outlives_no_worker() {
    use crate::audit_authority::NetconfWorkerBinding;
    let original = std::sync::Arc::new([0x61; 32]);
    let clone = original.clone();
    let replacement = std::sync::Arc::new([0x61; 32]);
    let binding = NetconfWorkerBinding::new(&original);
    assert!(binding.belongs_to(&clone));
    assert!(!binding.belongs_to(&replacement));
    drop(original);
    assert!(binding.belongs_to(&clone));
    drop(clone);
    let later = std::sync::Arc::new([0x61; 32]);
    assert!(!binding.belongs_to(&later));
}

#[tokio::test]
async fn target_device_preparation_preserves_reboot_cleanup_before_serving() {
    use crate::audit_authority::{NetconfDeviceOwner, NetconfWorkerBinding};
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let tentative = fixture.pending_fixture(&conn, true);
    assert!(matches!(
        fixture.submit(&conn, &tentative),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &tentative);
    let event = fixture.device_event(175);
    let effect = fixture
        .device_view(&conn)
        .prepare(&event, 160, [0x57; 16], [0x58; 16])
        .unwrap();
    let worker = std::sync::Arc::new(());
    let owner = NetconfDeviceOwner {
        worker: NetconfWorkerBinding::new(&worker),
        authority: fixture.identity,
        profile_incarnation: effect.profile_incarnation,
        device_incarnation: effect.device_incarnation,
        caller: event.caller,
    };
    let stale = fixture.prepare(effect, event);
    assert_eq!(fixture.device_view(&conn).running_version, 2);
    assert_eq!(stale.handle.body.binding.base_version, 0);
    assert_eq!(
        fixture.preflight(&conn, &stale, 100),
        Err(AuditAuthorityError::BindingMismatch)
    );
    let prepared = fixture.rebind_at(&conn, stale, 100);
    assert!(matches!(
        fixture.submit(&conn, &prepared),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &prepared);
    let view = fixture.device_view(&conn);
    assert!(!view.unsettled);
    assert!(view.cleanup_pending);
    assert_eq!(
        view.verify_owner(&owner),
        Err(AuditAuthorityError::RecoveryRequired)
    );
    assert!(matches!(
        view.prepare(&fixture.device_event(176), 160, [0x59; 16], [0x5a; 16]),
        Err(AuditAuthorityError::RecoveryRequired)
    ));
    let rollback = fixture.resolve_fixture(&conn, 177, 14, true, 100);
    assert!(matches!(
        fixture.submit(&conn, &rollback),
        AuditOperationState::TargetV1(_)
    ));
    fixture.assert_running_plaintext(&conn, &rollback);
    fixture.settle(&conn, &rollback);
    fixture.assert_no_pending(&conn);
    assert_eq!(fixture.device_view(&conn).verify_owner(&owner), Ok(()));
}

impl Fixture {
    fn session_owner(
        &self,
        conn: &Connection,
        worker: &std::sync::Arc<()>,
        session: u8,
    ) -> crate::audit_authority::NetconfSessionOwner {
        use crate::audit_authority::{
            NetconfDeviceOwner, NetconfSessionOwner, NetconfWorkerBinding,
        };
        let view = self.device_view(conn);
        let device = NetconfDeviceOwner {
            worker: NetconfWorkerBinding::new(worker),
            authority: view.authority,
            profile_incarnation: view.profile_incarnation.unwrap(),
            device_incarnation: view.device_incarnation.unwrap(),
            caller: view.caller.unwrap(),
        };
        NetconfSessionOwner::new(device, self.event(180).caller, [session; 16]).unwrap()
    }
}

#[tokio::test]
async fn target_session_locks_bind_all_datastores_and_refuse_stale_or_foreign_leases() {
    use crate::audit_authority::{
        NetconfLockDatastore as Store, NetconfLockLease, PreparedNetconfLock,
    };
    for datastore in [Store::Running, Store::Candidate, Store::Startup] {
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        fixture.active(&conn);
        let worker = std::sync::Arc::new(());
        let session = fixture.session_owner(&conn, &worker, 0x61);
        let foreign = fixture.session_owner(&conn, &worker, 0x62);
        assert_eq!(session.caller, foreign.caller);
        let event = fixture.event(180);
        let effect = fixture
            .device_view(&conn)
            .prepare_lock(&session, &event, datastore, None, 160)
            .unwrap();
        let mutation = fixture.prepare(effect, event);
        let prepared = PreparedNetconfLock {
            session: session.clone(),
            datastore,
            prepared: mutation.clone(),
        };
        assert_eq!(prepared.mutation(), &mutation);
        let lease = NetconfLockLease {
            session: session.clone(),
            datastore,
            incarnation: 1,
        };
        assert_eq!(
            fixture.device_view(&conn).verify_lease(&lease),
            Err(AuditAuthorityError::BindingMismatch)
        );
        assert_eq!(fixture.preflight(&conn, &mutation, 100).unwrap(), None);
        assert!(matches!(
            fixture.submit(&conn, &mutation),
            AuditOperationState::TargetV1(_)
        ));
        assert_eq!(
            fixture.device_view(&conn).verify_lease(&lease),
            Err(AuditAuthorityError::RecoveryRequired)
        );
        fixture.settle(&conn, &mutation);
        assert_eq!(fixture.device_view(&conn).verify_lease(&lease), Ok(()));
        assert!(matches!(
            fixture.device_view(&conn).prepare_lock(
                &foreign,
                &fixture.event(181),
                datastore,
                Some(&lease),
                160
            ),
            Err(AuditAuthorityError::BindingMismatch)
        ));
        let counterfeit = NetconfLockLease {
            session: foreign.clone(),
            ..lease.clone()
        };
        assert_eq!(
            fixture.device_view(&conn).verify_lease(&counterfeit),
            Err(AuditAuthorityError::BindingMismatch)
        );
        if datastore == Store::Candidate {
            let staged = fixture.encrypted(fixture.request(&conn, 181, 4, 0x61, 1), 0x37);
            assert!(matches!(
                fixture.submit(&conn, &staged),
                AuditOperationState::TargetV1(_)
            ));
            fixture.settle(&conn, &staged);
            assert_eq!(
                row(&conn, "config_netconf_targets", "target", 0)["generation"],
                1
            );
        }
        let event = fixture.event(182);
        let effect = fixture
            .device_view(&conn)
            .prepare_lock(&session, &event, datastore, Some(&lease), 160)
            .unwrap();
        let release = fixture.prepare(effect, event);
        assert!(matches!(
            fixture.submit(&conn, &release),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &release);
        assert_eq!(
            fixture.device_view(&conn).verify_lease(&lease),
            Err(AuditAuthorityError::BindingMismatch)
        );
        if datastore == Store::Candidate {
            let row = row(&conn, "config_netconf_targets", "target", 0);
            assert_eq!(row["generation"], 2);
            assert_eq!(row["present"], false);
            assert!(row["encrypted_envelope"].is_null());
        }
        let event = fixture.event(183);
        let effect = fixture
            .device_view(&conn)
            .prepare_lock(&session, &event, datastore, None, 160)
            .unwrap();
        let reacquire = fixture.prepare(effect, event);
        assert!(matches!(
            fixture.submit(&conn, &reacquire),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &reacquire);
        assert_eq!(
            fixture.device_view(&conn).verify_lease(&lease),
            Err(AuditAuthorityError::BindingMismatch)
        );
        let current = NetconfLockLease {
            incarnation: 3,
            ..lease.clone()
        };
        assert_eq!(fixture.device_view(&conn).verify_lease(&current), Ok(()));
        assert!(matches!(
            fixture.device_view(&conn).prepare_lock(
                &session,
                &fixture.event(184),
                datastore,
                Some(&lease),
                160
            ),
            Err(AuditAuthorityError::BindingMismatch)
        ));
        assert_eq!(format!("{session:?} {prepared:?} {current:?}"),"NetconfSessionOwner(<redacted>) PreparedNetconfLock(<redacted>) NetconfLockLease(<redacted>)");
    }
}

#[tokio::test]
async fn target_session_invalidation_reaches_clones_and_cannot_be_reactivated_by_equal_values() {
    use crate::audit_authority::{NetconfLockDatastore, NetconfSessionOwner};
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    let clone = session.clone();
    let equal = fixture.session_owner(&conn, &worker, 0x61);
    assert!(session.same_session(&clone));
    assert!(!session.same_session(&equal));
    assert_eq!(fixture.device_view(&conn).verify_session(&clone), Ok(()));
    assert!(matches!(
        NetconfSessionOwner::new(session.device.clone(), session.caller, [0; 16]),
        Err(AuditAuthorityError::InvalidInput)
    ));
    session.invalidate();
    clone.invalidate();
    assert_eq!(
        session.require_active(),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert_eq!(
        clone.require_active(),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert_eq!(
        fixture.device_view(&conn).verify_session(&clone),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert!(matches!(
        fixture.device_view(&conn).prepare_lock(
            &clone,
            &fixture.event(185),
            NetconfLockDatastore::Running,
            None,
            160
        ),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert!(equal.require_active().is_ok());
    assert!(!equal.same_session(&session));
}

#[tokio::test]
async fn target_session_preparation_refuses_wrong_caller_transport_operation_and_old_device() {
    use crate::audit_authority::{AuditCaller, NetconfLockDatastore};
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    let view = fixture.device_view(&conn);
    let before = target_rows(&conn);
    let changes = conn.total_changes();
    for variant in 0..3 {
        let mut event = fixture.event(186);
        match variant {
            0 => {
                event.caller = AuditCaller::project(
                    &fixture.privacy,
                    "fixture-tenant",
                    "fixture-other-principal",
                )
                .unwrap()
            }
            1 => event.transport = ManagementAuditTransportCode::Internal,
            _ => event.operation = ManagementAuditOperationCode::Read,
        }
        assert!(matches!(
            view.prepare_lock(&session, &event, NetconfLockDatastore::Running, None, 160),
            Err(AuditAuthorityError::BindingMismatch)
        ));
    }
    assert_eq!(conn.total_changes(), changes);
    assert_eq!(target_rows(&conn), before);
    let event = fixture.device_event(187);
    let effect = view.prepare(&event, 160, [0x57; 16], [0x58; 16]).unwrap();
    let replacement = fixture.prepare(effect, event);
    assert!(matches!(
        fixture.submit(&conn, &replacement),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &replacement);
    assert_eq!(
        fixture.device_view(&conn).verify_session(&session),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert!(
        session.require_active().is_ok(),
        "local activity must not replace retained device verification"
    );
}

#[tokio::test]
async fn target_session_cleanup_retains_one_original_across_clones_and_concurrent_retry() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    session.invalidate();
    let event = fixture.device_event(190);
    let effect = fixture
        .device_view(&conn)
        .prepare_session_cleanup(&session, &event, 160)
        .unwrap();
    let original = fixture.prepare(effect, event.clone());
    let later = fixture.rebind_at(&conn, original.clone(), 101);
    assert_ne!(original, later);
    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            session.retain_cleanup(original.clone()).unwrap()
        });
        let two = scope.spawn(|| {
            barrier.wait();
            session.clone().retain_cleanup(later.clone()).unwrap()
        });
        (one.join().unwrap(), two.join().unwrap())
    });
    assert_eq!(outcomes.0, outcomes.1);
    assert!(outcomes.0 == original || outcomes.0 == later);
    let selected = outcomes.0;
    assert_eq!(
        session
            .clone()
            .original_cleanup(&event, Duration::from_secs(60))
            .unwrap(),
        Some(selected.clone())
    );
    assert_eq!(session.retain_cleanup(later).unwrap(), selected);
    assert_eq!(session.retain_cleanup(original).unwrap(), selected);
    assert!(matches!(
        session.original_cleanup(&fixture.device_event(191), Duration::from_secs(60)),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert!(matches!(
        session.original_cleanup(&event, Duration::from_secs(61)),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    let mut changed = event.clone();
    changed.operation = ManagementAuditOperationCode::Read;
    assert!(matches!(
        session.original_cleanup(&changed, Duration::from_secs(60)),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert_eq!(
        fixture.ledger(&conn).operations.len(),
        1,
        "preparation must not admit an intent"
    );
    assert_eq!(
        session.require_active(),
        Err(AuditAuthorityError::BindingMismatch)
    );
}

#[tokio::test]
async fn target_session_cleanup_requires_original_scope_and_revoked_local_authority() {
    use crate::audit_authority::AuditCaller;
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    let event = fixture.device_event(192);
    let view = fixture.device_view(&conn);
    assert!(matches!(
        view.prepare_session_cleanup(&session, &event, 160),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    session.invalidate();
    for variant in 0..4 {
        let mut changed = event.clone();
        match variant {
            0 => {
                changed.caller =
                    AuditCaller::project(&fixture.privacy, "fixture-tenant", "fixture-other")
                        .unwrap()
            }
            1 => changed.transport = ManagementAuditTransportCode::NetconfSsh,
            2 => changed.operation = ManagementAuditOperationCode::Read,
            _ => changed.outcome = ManagementAuditOutcomeCode::Success,
        }
        assert!(matches!(
            view.prepare_session_cleanup(&session, &changed, 160),
            Err(AuditAuthorityError::BindingMismatch)
        ));
    }
    let effect = view.prepare_session_cleanup(&session, &event, 160).unwrap();
    let mut wrong_session = fixture.prepare(effect, event.clone());
    wrong_session.effect.resolution = Some(TargetResolutionV1::EndSession {
        session: [0x62; 16],
    });
    assert!(matches!(
        session.retain_cleanup(wrong_session),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert!(session
        .original_cleanup(&event, Duration::from_secs(60))
        .unwrap()
        .is_none());
    let replacement_event = fixture.device_event(193);
    let replacement = fixture.prepare(
        view.prepare(&replacement_event, 160, [0x57; 16], [0x58; 16])
            .unwrap(),
        replacement_event,
    );
    assert!(matches!(
        fixture.submit(&conn, &replacement),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &replacement);
    assert!(matches!(
        fixture
            .device_view(&conn)
            .prepare_session_cleanup(&session, &event, 160),
        Err(AuditAuthorityError::BindingMismatch)
    ));
}

#[tokio::test]
async fn target_session_cleanup_discards_only_owned_candidate_and_preserves_foreign_lease() {
    use crate::audit_authority::{NetconfLockDatastore, NetconfLockLease};
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    let foreign = fixture.session_owner(&conn, &worker, 0x62);
    for (request, slot, owner) in [(194, 0, 0x61), (195, 1, 0x61), (196, 2, 0x62)] {
        let lock = fixture.request(&conn, request, 2, owner, slot);
        assert!(matches!(
            fixture.submit(&conn, &lock),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &lock);
    }
    let stage = fixture.encrypted(fixture.request(&conn, 197, 4, 0x61, 1), 0x39);
    assert!(matches!(
        fixture.submit(&conn, &stage),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &stage);
    let foreign_lease = NetconfLockLease {
        session: foreign,
        datastore: NetconfLockDatastore::Startup,
        incarnation: 1,
    };
    assert_eq!(
        fixture.device_view(&conn).verify_lease(&foreign_lease),
        Ok(())
    );
    let before = target_rows(&conn);
    let startup = row(&conn, "config_netconf_lifecycle", "singleton", 1)["locks"][2].clone();
    session.invalidate();
    let event = fixture.device_event(198);
    let effect = fixture
        .device_view(&conn)
        .prepare_session_cleanup(&session, &event, 160)
        .unwrap();
    let cleanup = session
        .retain_cleanup(fixture.prepare(effect, event.clone()))
        .unwrap();
    assert_eq!(target_rows(&conn), before);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(cleanup.clone()))),
            100,
        )
        .unwrap();
    assert_eq!(
        target_rows(&conn),
        before,
        "intent admission is not cleanup"
    );
    assert!(fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(cleanup.clone()))),
            100
        )
        .is_err());
    assert_eq!(
        target_rows(&conn),
        before,
        "uncheckpointed intent grants no cleanup"
    );
    fixture.checkpoint(&conn);
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(cleanup.clone()))),
            100,
        )
        .unwrap();
    let known = fixture
        .ledger(&conn)
        .lookup(&fixture.key, cleanup.handle(), session.caller)
        .unwrap()
        .unwrap();
    assert!(matches!(known.state(), AuditOperationState::TargetV1(_)));
    assert!(!known.terminal_recorded());
    let candidate = row(&conn, "config_netconf_targets", "target", 0);
    assert_eq!(candidate["generation"], 2);
    assert_eq!(candidate["present"], false);
    assert!(candidate["encrypted_envelope"].is_null());
    let lifecycle = row(&conn, "config_netconf_lifecycle", "singleton", 1);
    assert_eq!(lifecycle["locks"][0]["incarnation"], 2);
    assert_eq!(lifecycle["locks"][1]["incarnation"], 2);
    assert!(lifecycle["locks"][0]["session"].is_null());
    assert!(lifecycle["locks"][1]["session"].is_null());
    assert_eq!(lifecycle["locks"][2], startup);
    assert_eq!(
        fixture.device_view(&conn).verify_owner(&session.device),
        Err(AuditAuthorityError::RecoveryRequired)
    );
    fixture.settle(&conn, &cleanup);
    assert_eq!(
        fixture.device_view(&conn).verify_lease(&foreign_lease),
        Ok(())
    );
    let after = target_rows(&conn);
    assert_eq!(fixture.submit(&conn, &cleanup), known.state());
    assert_eq!(
        target_rows(&conn),
        after,
        "original replay must not advance counters"
    );
    assert_eq!(
        session
            .clone()
            .original_cleanup(&event, Duration::from_secs(60))
            .unwrap(),
        Some(cleanup.clone())
    );
    let reopened = Connection::open(fixture.directory.path().join("authority.sqlite")).unwrap();
    assert_eq!(
        fixture
            .ledger(&reopened)
            .recover_target(&fixture.key, cleanup.handle(), session.caller)
            .unwrap(),
        cleanup
    );
    assert_eq!(
        fixture
            .ledger(&reopened)
            .lookup(&fixture.key, cleanup.handle(), session.caller)
            .unwrap()
            .unwrap()
            .state(),
        known.state()
    );
}

impl Fixture {
    fn cleanup_at(
        &self,
        conn: &Connection,
        session: &crate::audit_authority::NetconfSessionOwner,
        request: u8,
        now: i64,
    ) -> PreparedTargetMutation {
        let event = self.device_event(request);
        let effect = self
            .device_view(conn)
            .prepare_session_cleanup(session, &event, now + 60)
            .unwrap();
        self.rebind_at(conn, self.prepare(effect, event), now)
    }

    fn expire_cleanup(&self, conn: &Connection, original: &PreparedTargetMutation) {
        self.apply(
            conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(original.clone()))),
            original.handle.body.issued_at,
        )
        .unwrap();
        self.checkpoint(conn);
        assert!(self
            .apply(
                conn,
                AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(
                    original.clone()
                ))),
                original.handle.body.expires_at,
            )
            .is_err());
        assert_eq!(
            self.ledger(conn)
                .lookup(&self.key, original.handle(), original.effect.caller)
                .unwrap()
                .unwrap()
                .state(),
            AuditOperationState::Rejected
        );
    }
}

#[tokio::test]
async fn target_cleanup_successor_requires_expiry_rejection_terminal_and_checkpoint() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    session.invalidate();
    let original = session
        .retain_cleanup(fixture.cleanup_at(&conn, &session, 201, 100))
        .unwrap();
    let original_bytes = original.encode().unwrap();
    let successor = fixture.cleanup_at(&conn, &session, 202, 160);
    let before = target_rows(&conn);
    assert!(
        session
            .retain_cleanup_successor(
                &original,
                successor.clone(),
                &fixture.ledger(&conn),
                &fixture.key,
                160
            )
            .is_err(),
        "missing original is not rejection"
    );
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(original.clone()))),
            100,
        )
        .unwrap();
    fixture.checkpoint(&conn);
    assert!(
        matches!(
            session.retain_cleanup_successor(
                &original,
                successor.clone(),
                &fixture.ledger(&conn),
                &fixture.key,
                160
            ),
            Err(AuditAuthorityError::RecoveryRequired)
        ),
        "expired intent is still unresolved"
    );
    assert!(fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(original.clone()))),
            160
        )
        .is_err());
    assert_eq!(
        fixture
            .ledger(&conn)
            .lookup(&fixture.key, original.handle(), session.caller)
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Rejected
    );
    assert!(
        matches!(
            session.retain_cleanup_successor(
                &original,
                successor.clone(),
                &fixture.ledger(&conn),
                &fixture.key,
                160
            ),
            Err(AuditAuthorityError::RecoveryRequired)
        ),
        "rejection without terminal is unsettled"
    );
    fixture
        .apply(&conn, AuditCommand::Terminal(original.handle.clone()), 160)
        .unwrap();
    assert!(
        matches!(
            session.retain_cleanup_successor(
                &original,
                successor.clone(),
                &fixture.ledger(&conn),
                &fixture.key,
                160
            ),
            Err(AuditAuthorityError::RecoveryRequired)
        ),
        "terminal without independent checkpoint is unsettled"
    );
    fixture.checkpoint(&conn);
    assert!(
        matches!(
            session.retain_cleanup_successor(
                &original,
                successor.clone(),
                &fixture.ledger(&conn),
                &fixture.key,
                159
            ),
            Err(AuditAuthorityError::RecoveryRequired)
        ),
        "original expiry must have elapsed"
    );
    let changes = conn.total_changes();
    assert_eq!(
        session
            .retain_cleanup_successor(
                &original,
                successor.clone(),
                &fixture.ledger(&conn),
                &fixture.key,
                160
            )
            .unwrap(),
        successor
    );
    assert_eq!(
        conn.total_changes(),
        changes,
        "preparation must not admit or apply cleanup"
    );
    assert_eq!(target_rows(&conn), before);
    assert_eq!(original.encode().unwrap(), original_bytes);
    assert_eq!(
        session.require_active(),
        Err(AuditAuthorityError::BindingMismatch)
    );
    assert!(fixture
        .ledger(&conn)
        .lookup(&fixture.key, successor.handle(), session.caller)
        .unwrap()
        .is_none());
    let reopened = Connection::open(fixture.directory.path().join("authority.sqlite")).unwrap();
    assert_eq!(
        fixture
            .ledger(&reopened)
            .recover_target(&fixture.key, original.handle(), session.caller)
            .unwrap(),
        original
    );
    assert_eq!(
        fixture
            .ledger(&reopened)
            .lookup(&fixture.key, original.handle(), session.caller)
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Rejected
    );
}

#[tokio::test]
async fn target_cleanup_successor_selects_one_concurrent_attempt_and_rejects_stale_predecessors() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    session.invalidate();
    let original = session
        .retain_cleanup(fixture.cleanup_at(&conn, &session, 203, 100))
        .unwrap();
    fixture.expire_cleanup(&conn, &original);
    fixture.settle(&conn, &original);
    let first = fixture.cleanup_at(&conn, &session, 204, 160);
    let later = fixture.cleanup_at(&conn, &session, 204, 161);
    assert_ne!(first, later);
    let ledger = fixture.ledger(&conn);
    let key = fixture.key.clone();
    let before = target_rows(&conn);
    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            session
                .retain_cleanup_successor(&original, first.clone(), &ledger, &key, 161)
                .unwrap()
        });
        let two = scope.spawn(|| {
            barrier.wait();
            session
                .clone()
                .retain_cleanup_successor(&original, later.clone(), &ledger, &key, 161)
                .unwrap()
        });
        (one.join().unwrap(), two.join().unwrap())
    });
    let selected = outcomes.0;
    assert_eq!(selected, outcomes.1);
    assert!(selected == first || selected == later);
    assert_eq!(
        session
            .successor_cleanup(
                &original,
                &fixture.device_event(204),
                Duration::from_secs(60)
            )
            .unwrap(),
        Some(selected.clone())
    );
    assert!(matches!(
        session.successor_cleanup(
            &original,
            &fixture.device_event(205),
            Duration::from_secs(60)
        ),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert!(matches!(
        session.successor_cleanup(
            &original,
            &fixture.device_event(204),
            Duration::from_secs(61)
        ),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert!(matches!(
        session.successor_cleanup(
            &original,
            &fixture.device_event(203),
            Duration::from_secs(60)
        ),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    let competing = fixture.cleanup_at(&conn, &session, 205, 162);
    assert!(matches!(
        session.retain_cleanup_successor(&original, competing, &ledger, &key, 162),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert_eq!(target_rows(&conn), before);
    fixture.expire_cleanup(&conn, &selected);
    fixture.settle(&conn, &selected);
    let next = fixture.cleanup_at(&conn, &session, 206, 222);
    assert_eq!(
        session
            .retain_cleanup_successor(
                &selected,
                next.clone(),
                &fixture.ledger(&conn),
                &fixture.key,
                222
            )
            .unwrap(),
        next
    );
    assert!(
        matches!(
            session.successor_cleanup(
                &original,
                &fixture.device_event(206),
                Duration::from_secs(60)
            ),
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "an old predecessor cannot select the current attempt"
    );
    assert!(matches!(
        session.retain_cleanup_successor(
            &original,
            next.clone(),
            &fixture.ledger(&conn),
            &fixture.key,
            222
        ),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert_eq!(
        session
            .clone()
            .original_cleanup(&fixture.device_event(206), Duration::from_secs(60))
            .unwrap(),
        Some(next)
    );
    for old in [&original, &selected] {
        assert_eq!(
            fixture
                .ledger(&conn)
                .recover_target(&fixture.key, old.handle(), session.caller)
                .unwrap(),
            *old
        );
        assert_eq!(
            fixture
                .ledger(&conn)
                .lookup(&fixture.key, old.handle(), session.caller)
                .unwrap()
                .unwrap()
                .state(),
            AuditOperationState::Rejected
        );
    }
    assert_eq!(target_rows(&conn), before);
}

#[tokio::test]
async fn target_cleanup_successor_refuses_applied_cleanup_and_other_session_scope() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    session.invalidate();
    let original = session
        .retain_cleanup(fixture.cleanup_at(&conn, &session, 207, 100))
        .unwrap();
    assert!(matches!(
        fixture.submit(&conn, &original),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &original);
    let successor = fixture.cleanup_at(&conn, &session, 208, 160);
    assert!(matches!(
        session.retain_cleanup_successor(
            &original,
            successor,
            &fixture.ledger(&conn),
            &fixture.key,
            160
        ),
        Err(AuditAuthorityError::RecoveryRequired)
    ));
    let other = fixture.session_owner(&conn, &worker, 0x62);
    other.invalidate();
    assert!(matches!(
        other.successor_cleanup(
            &original,
            &fixture.device_event(208),
            Duration::from_secs(60)
        ),
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert_eq!(
        session
            .original_cleanup(&fixture.device_event(207), Duration::from_secs(60))
            .unwrap(),
        Some(original)
    );
}

#[tokio::test]
async fn target_cleanup_successor_refuses_pruned_original_without_changing_pending_rollback() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    let tentative = fixture.pending_fixture(&conn, true);
    assert!(matches!(
        fixture.submit(&conn, &tentative),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &tentative);
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    session.invalidate();
    let original = session
        .retain_cleanup(fixture.cleanup_at(&conn, &session, 209, 100))
        .unwrap();
    fixture.expire_cleanup(&conn, &original);
    fixture.settle(&conn, &original);
    let before = target_rows(&conn);
    let successor = fixture.cleanup_at(&conn, &session, 210, 200);
    let ledger = fixture.ledger(&conn);
    assert_eq!(
        original.verify_settled_cleanup_rejection(&session, &ledger, &fixture.key, 200),
        Ok(())
    );
    // The fixture is the authority. This is a real acknowledged-prefix prune,
    // not a recipient verification guarantee or a fabricated missing receipt.
    let mut body = ledger
        .continuity
        .as_ref()
        .unwrap()
        .checkpoint
        .as_ref()
        .unwrap()
        .body
        .clone();
    body.acknowledged_export = [0x78; 32];
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
    let pruned = fixture.ledger(&conn);
    assert!(pruned
        .lookup(&fixture.key, original.handle(), session.caller)
        .unwrap()
        .is_none());
    assert!(
        session
            .retain_cleanup_successor(&original, successor, &pruned, &fixture.key, 200)
            .is_err(),
        "pruned rejection cannot authorize a new cleanup"
    );
    assert_eq!(
        session
            .original_cleanup(&fixture.device_event(209), Duration::from_secs(60))
            .unwrap(),
        Some(original)
    );
    assert_eq!(
        target_rows(&conn),
        before,
        "pending parent and deadline must remain unchanged"
    );
}

fn copy_plaintext(request: u8, config: &[u8]) -> Vec<u8> {
    let mut bytes = b"\x89OPCCFG\x02\r\n\x1a\n{\"config\":".to_vec();
    bytes.extend_from_slice(config);
    bytes.extend_from_slice(
        format!(",\"request_id\":\"00000000-0000-4000-8000-{request:012x}\"}}").as_bytes(),
    );
    bytes
}

async fn copy_provider_stage(
    fixture: &Fixture,
    conn: &Connection,
    slot: u8,
    config: &[u8],
) -> (
    opc_key::MemoryKeyProvider,
    crate::consensus::audit_mutation::TargetEncryptedBlobV1,
) {
    use crate::consensus::audit_mutation::TargetPayloadV1;
    use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider};
    use sha2::{Digest, Sha256};
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("fixture-target-key").unwrap(),
            KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([0x6a; 32]),
        )
        .unwrap();
    let mut stage = fixture.encrypted(
        fixture.request(conn, 180, if slot == 0 { 4 } else { 7 }, 0x61, slot + 1),
        0x6a,
    );
    let Some(TargetPayloadV1::Target(blob)) = &mut stage.effect.encrypted_payload else {
        panic!("target copy fixture");
    };
    let envelope = opc_crypto::CryptoEnvelopeRef::decode(&blob.encrypted_blob).unwrap();
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
    let plaintext = copy_plaintext(180, config);
    let encrypted = opc_crypto::encrypt_attested_envelope(&provider, &aad, &plaintext)
        .await
        .unwrap();
    blob.encrypted_blob = encrypted.encoded().to_vec();
    blob.plaintext_digest = Sha256::digest(&plaintext).into();
    let source = blob.clone();
    let stage = fixture.rebind_at(conn, stage, 100);
    assert!(matches!(
        fixture.submit(conn, &stage),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(conn, &stage);
    provider
        .insert_active_key(
            KeyId::new("fixture-running-key").unwrap(),
            KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([0x7b; 32]),
        )
        .unwrap();
    (provider, source)
}

async fn copy_provider_destination(
    fixture: &Fixture,
    conn: &Connection,
    provider: &opc_key::MemoryKeyProvider,
    slot: u8,
    request: u8,
    config: &[u8],
) -> PreparedTargetMutation {
    use crate::consensus::audit_mutation::TargetPayloadV1;
    use sha2::{Digest, Sha256};
    let mut prepared = fixture.running_target(conn, request, 15, slot, 0x6a);
    let Some(TargetPayloadV1::Running { commit, .. }) = &mut prepared.effect.encrypted_payload
    else {
        panic!("running copy fixture");
    };
    let envelope = opc_crypto::CryptoEnvelopeRef::decode(&commit.record.encrypted_blob).unwrap();
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
    let plaintext = copy_plaintext(request, config);
    let encrypted = opc_crypto::encrypt_attested_envelope(provider, &aad, &plaintext)
        .await
        .unwrap();
    let mut record = commit.record.clone();
    record.encrypted_blob = encrypted.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    let attested =
        crate::AttestedConfigCommit::try_new(record, Vec::new(), encrypted.claim().unwrap())
            .unwrap();
    let (record, audit, _) = attested.into_parts();
    **commit =
        crate::consensus::PreparedConfigCommit::prepare(record, audit, &fixture.key).unwrap();
    fixture.rebind_at(conn, prepared, 100)
}

async fn bind_copy_provider(
    fixture: &Fixture,
    conn: &Connection,
    provider: &dyn opc_key::KeyProvider,
    source: &crate::consensus::audit_mutation::TargetEncryptedBlobV1,
    mut prepared: PreparedTargetMutation,
) -> Result<PreparedTargetMutation, AuditAuthorityError> {
    prepared.effect.bind_provider_copy(provider, source).await?;
    Ok(fixture.rebind_at(conn, prepared, 100))
}

#[tokio::test]
async fn target_provider_copy_accepts_distinct_authenticated_replay_wrappers() {
    use crate::consensus::audit_mutation::TargetPayloadV1;
    for slot in [0, 1] {
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        fixture.active(&conn);
        let config = br#"{"limit":9007199254740993,"items":[1,2]}"#;
        let (provider, source) = copy_provider_stage(&fixture, &conn, slot, config).await;
        let prepared =
            copy_provider_destination(&fixture, &conn, &provider, slot, 181, config).await;
        let prepared = bind_copy_provider(&fixture, &conn, &provider, &source, prepared)
            .await
            .unwrap();
        let (commit, _) = prepared
            .effect
            .encrypted_payload
            .as_ref()
            .and_then(TargetPayloadV1::running)
            .unwrap();
        assert_ne!(commit.record.plaintext_digest, source.plaintext_digest);
        for (ciphertext, expected) in [
            (&source.encrypted_blob, copy_plaintext(180, config)),
            (&commit.record.encrypted_blob, copy_plaintext(181, config)),
        ] {
            let envelope = opc_crypto::CryptoEnvelopeRef::decode(ciphertext).unwrap();
            let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
            let decoded = opc_crypto::decrypt_envelope(&provider, &aad, ciphertext)
                .await
                .unwrap();
            assert_eq!(
                *decoded, expected,
                "exact configuration and original replay wrapper"
            );
        }
        let before = row(&conn, "config_netconf_targets", "target", slot);
        assert!(
            matches!(fixture.submit(&conn, &prepared), AuditOperationState::TargetV1(r)
                if matches!(r.outcome(), NetconfAppliedOutcome::CopiedRunning { running_version: 1 })),
            "provider-authenticated copy of identical configuration rejected distinct replay wrappers"
        );
        assert_eq!(row(&conn, "config_netconf_targets", "target", slot), before);
        let retained: Vec<u8> = conn
            .query_row(
                "SELECT encrypted_blob FROM config_history WHERE version=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(retained, commit.record.encrypted_blob);
        fixture.settle(&conn, &prepared);
    }
}

#[tokio::test]
async fn target_provider_copy_refuses_content_substitution_and_authentication_failure_before_intent(
) {
    use crate::consensus::audit_mutation::TargetPayloadV1;
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let config = br#"{"limit":9007199254740993}"#;
    let (provider, source) = copy_provider_stage(&fixture, &conn, 0, config).await;
    let before = target_rows(&conn);
    let sequence = fixture.ledger(&conn).sequence;
    // Adjacent large numbers must never become equal through float conversion.
    let wrong = copy_provider_destination(
        &fixture,
        &conn,
        &provider,
        0,
        181,
        br#"{"limit":9007199254740992}"#,
    )
    .await;
    assert!(
        matches!(
            bind_copy_provider(&fixture, &conn, &provider, &source, wrong).await,
            Err(AuditAuthorityError::BindingMismatch)
        ),
        "provider copy accepted substituted configuration"
    );
    let exact = copy_provider_destination(&fixture, &conn, &provider, 0, 182, config).await;
    let mut false_digest = source.clone();
    false_digest.plaintext_digest[0] ^= 1;
    assert!(matches!(
        bind_copy_provider(&fixture, &conn, &provider, &false_digest, exact.clone()).await,
        Err(AuditAuthorityError::BindingMismatch)
    ));
    let mut tampered = source.clone();
    *tampered.encrypted_blob.last_mut().unwrap() ^= 1;
    assert!(
        bind_copy_provider(&fixture, &conn, &provider, &tampered, exact.clone())
            .await
            .is_err()
    );
    assert!(matches!(
        bind_copy_provider(
            &fixture,
            &conn,
            &opc_key::MemoryKeyProvider::new(),
            &source,
            exact.clone()
        )
        .await,
        Err(AuditAuthorityError::Unavailable)
    ));
    let mut tampered_destination = exact.clone();
    let Some(TargetPayloadV1::Running { commit, .. }) =
        &mut tampered_destination.effect.encrypted_payload
    else {
        panic!("running copy fixture");
    };
    *commit.record.encrypted_blob.last_mut().unwrap() ^= 1;
    assert!(
        bind_copy_provider(&fixture, &conn, &provider, &source, tampered_destination)
            .await
            .is_err()
    );
    let mut false_source = exact.clone();
    let Some(crate::consensus::audit_mutation::TargetSourceV1::Candidate {
        ciphertext_digest, ..
    }) = &mut false_source.effect.source
    else {
        panic!("candidate source fixture");
    };
    ciphertext_digest[0] ^= 1;
    assert!(matches!(
        bind_copy_provider(&fixture, &conn, &provider, &source, false_source).await,
        Err(AuditAuthorityError::BindingMismatch)
    ));
    assert_eq!(target_rows(&conn), before);
    assert_eq!(
        fixture.ledger(&conn).sequence,
        sequence,
        "failed provider preparation admitted an intent"
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM config_history", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert!(
        bind_copy_provider(&fixture, &conn, &provider, &source, exact)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn target_provider_copy_retains_source_and_authenticated_binding_fences() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let config = br#"{"enabled":true}"#;
    let (provider, source) = copy_provider_stage(&fixture, &conn, 0, config).await;
    let exact = copy_provider_destination(&fixture, &conn, &provider, 0, 181, config).await;
    let exact = bind_copy_provider(&fixture, &conn, &provider, &source, exact)
        .await
        .unwrap();
    let encoded = exact.encode().unwrap();
    assert!(
        !encoded.windows(config.len()).any(|w| w == config),
        "configuration entered closed recovery data"
    );
    let mut changed: Value = serde_json::from_slice(&encoded).unwrap();
    let binding = &mut changed["effect"]["encrypted_payload"]["provider-copy"]["binding"];
    binding["source_plaintext_digest"][0] =
        Value::from(binding["source_plaintext_digest"][0].as_u64().unwrap() ^ 1);
    let untrusted = PreparedTargetMutation::decode(&serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(
        untrusted.verify_effect(&fixture.key).is_err(),
        "decoded copy binding bypassed original effect authentication"
    );
    // Even an authority-side fault cannot substitute its claimed source digest
    // for the digest in the authenticated retained row.
    let corrupt = fixture.rebind_at(&conn, untrusted, 100);
    let before = target_rows(&conn);
    assert_eq!(
        fixture.submit(&conn, &corrupt),
        AuditOperationState::Rejected,
        "copy accepted an unrelated source plaintext digest"
    );
    assert_eq!(target_rows(&conn), before);
    fixture.settle(&conn, &corrupt);
    let old = copy_provider_destination(&fixture, &conn, &provider, 0, 182, config).await;
    let old = bind_copy_provider(&fixture, &conn, &provider, &source, old)
        .await
        .unwrap();
    let replacement = fixture.encrypted(fixture.request(&conn, 183, 4, 0x61, 1), 0x6b);
    assert!(matches!(
        fixture.submit(&conn, &replacement),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(&conn, &replacement);
    let before = target_rows(&conn);
    assert_eq!(
        fixture.submit(&conn, &old),
        AuditOperationState::Rejected,
        "provider binding bypassed exact source generation/ciphertext"
    );
    assert_eq!(target_rows(&conn), before);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM config_history", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    fixture.settle(&conn, &old);
}

#[tokio::test]
async fn target_provider_copy_pinned_preparation_binds_current_session_and_locks() {
    use crate::audit_authority::NetconfLockDatastore as Store;
    use crate::consensus::audit_mutation::TargetPayloadV1;
    for store in [Store::Candidate, Store::Startup] {
        let slot = if store == Store::Candidate { 0 } else { 1 };
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        fixture.active(&conn);
        let config = br#"{"enabled":true}"#;
        let (provider, source) = copy_provider_stage(&fixture, &conn, slot, config).await;
        let original =
            copy_provider_destination(&fixture, &conn, &provider, slot, 181, config).await;
        let Some(TargetPayloadV1::Running { commit, .. }) = original.effect.encrypted_payload
        else {
            panic!("running copy fixture");
        };
        let tx = conn.unchecked_transaction().unwrap();
        let view = crate::consensus::audit_targets::read_copy_view_sync(
            &tx,
            &fixture.key,
            &fixture.ledger(&tx),
            store,
            &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
        )
        .unwrap()
        .unwrap();
        tx.commit().unwrap();
        assert!(view.blob == source);
        let worker = std::sync::Arc::new(());
        let session = fixture.session_owner(&conn, &worker, 0x61);
        let mut effect = view
            .prepare(&session, &fixture.event(181), (*commit).clone(), 160)
            .unwrap();
        effect
            .bind_provider_copy(&provider, &view.blob)
            .await
            .unwrap();
        let prepared = fixture.rebind_at(&conn, fixture.prepare(effect, fixture.event(181)), 100);
        assert!(matches!(
            fixture.submit(&conn, &prepared),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &prepared);
        session.invalidate();
        assert!(matches!(
            view.prepare(&session, &fixture.event(182), *commit, 160),
            Err(AuditAuthorityError::BindingMismatch)
        ));
    }
}
fn provider_lifecycle_keys() -> opc_key::MemoryKeyProvider {
    let provider = opc_key::MemoryKeyProvider::new();
    for (name, seed) in [("fixture-target-key", 0x6a), ("fixture-running-key", 0x7b)] {
        provider
            .insert_active_key(
                opc_key::KeyId::new(name).unwrap(),
                opc_key::KeyPurpose::Config,
                opc_types::TenantId::from_static("fixture-tenant"),
                zeroize::Zeroizing::new([seed; 32]),
            )
            .unwrap();
    }
    provider
}

fn provider_history_blob(
    conn: &Connection,
    version: u64,
) -> crate::consensus::audit_mutation::TargetEncryptedBlobV1 {
    let (schema, digest, encrypted): (Vec<u8>, Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT schema_digest,plaintext_digest,encrypted_blob FROM config_history WHERE version=?1",
            [version],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    crate::consensus::audit_mutation::TargetEncryptedBlobV1 {
        schema: opc_types::SchemaDigest::from_bytes(schema.try_into().unwrap()),
        plaintext_digest: digest.try_into().unwrap(),
        encrypted_blob: encrypted,
    }
}

async fn provider_assert_history(
    conn: &Connection,
    provider: &dyn opc_key::KeyProvider,
    version: u64,
    request: u8,
    config: &[u8],
) {
    use sha2::{Digest, Sha256};
    let blob = provider_history_blob(conn, version);
    let envelope = opc_crypto::CryptoEnvelopeRef::decode(&blob.encrypted_blob).unwrap();
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
    assert_eq!(aad.version(), version);
    let plaintext = opc_crypto::decrypt_envelope(provider, &aad, &blob.encrypted_blob)
        .await
        .unwrap();
    assert_eq!(*plaintext, copy_plaintext(request, config));
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&plaintext)),
        blob.plaintext_digest
    );
}

async fn provider_rewrap_running(
    fixture: &Fixture,
    conn: &Connection,
    provider: &dyn opc_key::KeyProvider,
    mut prepared: PreparedTargetMutation,
    request: u8,
    config: &[u8],
) -> PreparedTargetMutation {
    use crate::consensus::audit_mutation::TargetPayloadV1;
    use sha2::{Digest, Sha256};
    let Some(TargetPayloadV1::Running { commit, .. }) = &mut prepared.effect.encrypted_payload
    else {
        panic!("running lifecycle fixture");
    };
    let envelope = opc_crypto::CryptoEnvelopeRef::decode(&commit.record.encrypted_blob).unwrap();
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
    let plaintext = copy_plaintext(request, config);
    let encrypted = opc_crypto::encrypt_attested_envelope(provider, &aad, &plaintext)
        .await
        .unwrap();
    let mut record = commit.record.clone();
    record.encrypted_blob = encrypted.encoded().to_vec();
    record.plaintext_digest = Sha256::digest(&plaintext).to_vec();
    let attested =
        crate::AttestedConfigCommit::try_new(record, Vec::new(), encrypted.claim().unwrap())
            .unwrap();
    let (record, audit, _) = attested.into_parts();
    **commit =
        crate::consensus::PreparedConfigCommit::prepare(record, audit, &fixture.key).unwrap();
    fixture.rebind_at(conn, prepared, 100)
}

async fn provider_stage_second_candidate(
    fixture: &Fixture,
    conn: &Connection,
    config: &[u8],
) -> crate::consensus::audit_mutation::TargetEncryptedBlobV1 {
    use crate::consensus::audit_mutation::TargetPayloadV1;
    use sha2::{Digest, Sha256};
    let provider = opc_key::MemoryKeyProvider::new();
    provider
        .insert_active_key(
            opc_key::KeyId::new("fixture-target-key").unwrap(),
            opc_key::KeyPurpose::Config,
            opc_types::TenantId::from_static("fixture-tenant"),
            zeroize::Zeroizing::new([0x6a; 32]),
        )
        .unwrap();
    let mut stage = fixture.encrypted(fixture.request(conn, 182, 4, 0x61, 1), 0x6a);
    let Some(TargetPayloadV1::Target(blob)) = &mut stage.effect.encrypted_payload else {
        panic!("second candidate fixture");
    };
    let envelope = opc_crypto::CryptoEnvelopeRef::decode(&blob.encrypted_blob).unwrap();
    let (aad, _) = opc_key::decode_bound_aad(envelope.aad).unwrap();
    let plaintext = copy_plaintext(182, config);
    let encrypted = opc_crypto::encrypt_attested_envelope(&provider, &aad, &plaintext)
        .await
        .unwrap();
    blob.encrypted_blob = encrypted.encoded().to_vec();
    blob.plaintext_digest = Sha256::digest(&plaintext).into();
    let source = blob.clone();
    let stage = fixture.rebind_at(conn, stage, 100);
    assert!(matches!(
        fixture.submit(conn, &stage),
        AuditOperationState::TargetV1(_)
    ));
    fixture.settle(conn, &stage);
    source
}

async fn provider_rollback(
    fixture: &Fixture,
    conn: &Connection,
    provider: &dyn opc_key::KeyProvider,
    action: u8,
    now: i64,
    config: &[u8],
) -> PreparedTargetMutation {
    use crate::consensus::audit_mutation::{TargetPayloadV1, TargetSourceV1};
    use opc_key::{ConfigAad, EnvelopeAad};
    use sha2::{Digest, Sha256};
    // Reuse only the ordinary confirmation identity/lock fixture. The copied
    // destination and original parent are constructed separately below.
    let mut prepared = fixture.resolve_fixture(conn, 184, 10, false, now);
    let lifecycle = row(conn, "config_netconf_lifecycle", "singleton", 1);
    let pending = &lifecycle["pending_confirmation"];
    let parent = &lifecycle["rollback_parent"];
    let version = pending["running_version"].as_u64().unwrap();
    let source = provider_history_blob(conn, parent["version"].as_u64().unwrap());
    let parent_tx = serde_json::from_value(pending["tx_id"].clone()).unwrap();
    let tx_id = opc_types::TxId::new();
    let committed_at = opc_types::Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(now).unwrap(),
    );
    let principal = r#"{"tenant":"fixture-tenant","subject":"fixture-principal"}"#.to_owned();
    let aad = EnvelopeAad::config(
        opc_types::TenantId::from_static("fixture-tenant"),
        version + 1,
        ConfigAad::new(
            tx_id,
            Some(parent_tx),
            committed_at,
            &principal,
            source.schema,
            "running",
        )
        .unwrap(),
    );
    let plaintext = copy_plaintext(184, config);
    let encrypted = opc_crypto::encrypt_attested_envelope(provider, &aad, &plaintext)
        .await
        .unwrap();
    let record = crate::CommitRecord {
        tx_id,
        parent_tx_id: Some(parent_tx),
        version: opc_types::ConfigVersion::new(version + 1),
        committed_at,
        principal,
        source: crate::CommitSource::CommitConfirmedRestore,
        schema_digest: source.schema,
        plaintext_digest: Sha256::digest(&plaintext).to_vec(),
        encrypted_blob: encrypted.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    };
    let attested =
        crate::AttestedConfigCommit::try_new(record, Vec::new(), encrypted.claim().unwrap())
            .unwrap();
    let (record, audit, _) = attested.into_parts();
    let commit =
        crate::consensus::PreparedConfigCommit::prepare(record, audit, &fixture.key).unwrap();
    prepared.effect.action = action.try_into().unwrap();
    prepared.effect.destination = TargetExpectationV1::Running { version };
    prepared.effect.source = Some(TargetSourceV1::Running {
        version: parent["version"].as_u64().unwrap(),
        schema: source.schema,
        ciphertext_digest: Sha256::digest(&source.encrypted_blob).into(),
    });
    prepared.effect.encrypted_payload = Some(TargetPayloadV1::Running {
        commit: Box::new(commit),
        confirmation_ownership: None,
    });
    if action == 12 || action == 14 {
        prepared.handle.body.event.transport = ManagementAuditTransportCode::Internal;
    }
    if action == 14 {
        prepared.effect.resolution = Some(TargetResolutionV1::RebootRecovery {
            previous_device: serde_json::from_value(pending["device_incarnation"].clone()).unwrap(),
            pending: Some(serde_json::from_value(pending["pending"].clone()).unwrap()),
            original_deadline: lifecycle["original_deadline"].as_i64(),
        });
    }
    prepared
        .effect
        .bind_provider_copy(provider, &source)
        .await
        .unwrap();
    fixture.rebind_at(conn, prepared, now)
}

#[tokio::test]
async fn target_provider_lifecycle_promotes_and_copies_exact_absent_candidate_fallback() {
    use crate::audit_authority::NetconfLockDatastore;
    use crate::consensus::audit_mutation::{TargetPayloadV1, TargetSourceV1};
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let config = br#"{"counter":9007199254740993,"enabled":true}"#;
    let (provider, source) = copy_provider_stage(&fixture, &conn, 0, config).await;
    let promote = fixture.running_target(&conn, 181, 6, 0, 0x6a);
    let promote = provider_rewrap_running(&fixture, &conn, &provider, promote, 181, config).await;
    let promote = bind_copy_provider(&fixture, &conn, &provider, &source, promote)
        .await
        .unwrap();
    assert!(
        matches!(fixture.submit(&conn, &promote), AuditOperationState::TargetV1(r)
        if matches!(r.outcome(), NetconfAppliedOutcome::Promoted { running_version: 1, retired_generation } if retired_generation.get() == 2))
    );
    fixture.settle(&conn, &promote);
    provider_assert_history(&conn, &provider, 1, 181, config).await;
    let candidate = row(&conn, "config_netconf_targets", "target", 0);
    assert_eq!(candidate["present"], false);
    let original = fixture.fallback_copy(&conn, 182);
    let original = provider_rewrap_running(&fixture, &conn, &provider, original, 182, config).await;
    let Some(TargetPayloadV1::Running { commit, .. }) = original.effect.encrypted_payload else {
        panic!("fallback fixture");
    };
    let tx = conn.unchecked_transaction().unwrap();
    let view = crate::consensus::audit_targets::read_copy_view_sync(
        &tx,
        &fixture.key,
        &fixture.ledger(&tx),
        NetconfLockDatastore::Candidate,
        &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
    )
    .unwrap()
    .unwrap();
    tx.commit().unwrap();
    assert!(matches!(
        view.source,
        TargetSourceV1::CandidateFallback {
            running_version: 1,
            ..
        }
    ));
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    let mut effect = view
        .prepare(&session, &fixture.event(182), *commit, 160)
        .unwrap();
    effect
        .bind_provider_copy(&provider, &view.blob)
        .await
        .unwrap();
    let fallback = fixture.rebind_at(&conn, fixture.prepare(effect, fixture.event(182)), 100);
    assert!(
        matches!(fixture.submit(&conn, &fallback), AuditOperationState::TargetV1(r)
        if matches!(r.outcome(), NetconfAppliedOutcome::CopiedRunning { running_version: 2 }))
    );
    assert_eq!(row(&conn, "config_netconf_targets", "target", 0), candidate);
    provider_assert_history(&conn, &provider, 2, 182, config).await;
    fixture.settle(&conn, &fallback);
}

#[tokio::test]
async fn target_provider_lifecycle_confirms_or_restores_exact_parent_for_each_resolution() {
    let original_config = br#"{"counter":9007199254740993,"enabled":false}"#;
    let tentative_config = br#"{"counter":9007199254740992,"enabled":true}"#;
    for action in [10, 11, 12, 14] {
        let fixture = Fixture::new().await;
        let shared = fixture.backend.conn();
        let conn = shared.lock().await;
        fixture.active(&conn);
        let (provider, source) = copy_provider_stage(&fixture, &conn, 0, original_config).await;
        let promote = fixture.running_target(&conn, 181, 6, 0, 0x6a);
        let promote =
            provider_rewrap_running(&fixture, &conn, &provider, promote, 181, original_config)
                .await;
        let promote = bind_copy_provider(&fixture, &conn, &provider, &source, promote)
            .await
            .unwrap();
        assert!(matches!(
            fixture.submit(&conn, &promote),
            AuditOperationState::TargetV1(_)
        ));
        fixture.settle(&conn, &promote);
        let source = provider_stage_second_candidate(&fixture, &conn, tentative_config).await;
        let tentative = fixture.tentative_target(&conn, 183, 0x6a);
        let tentative =
            provider_rewrap_running(&fixture, &conn, &provider, tentative, 183, tentative_config)
                .await;
        let tentative = bind_copy_provider(&fixture, &conn, &provider, &source, tentative)
            .await
            .unwrap();
        assert!(
            matches!(fixture.submit(&conn, &tentative), AuditOperationState::TargetV1(r)
            if matches!(r.outcome(), NetconfAppliedOutcome::Tentative { running_version: 2, retired_generation, .. } if retired_generation.get() == 4)),
            "provider copy did not atomically retain tentative ownership"
        );
        fixture.settle(&conn, &tentative);
        provider_assert_history(&conn, &provider, 1, 181, original_config).await;
        provider_assert_history(&conn, &provider, 2, 183, tentative_config).await;
        let retained = target_rows(&conn);
        let deadline = row(&conn, "config_netconf_lifecycle", "singleton", 1)["original_deadline"]
            .as_i64()
            .unwrap();
        drop(conn);
        drop(provider);
        // Reopen persisted rows and reconstruct a fresh provider using the same
        // synthetic custody material. This is component recovery, not a process
        // restart or public NETCONF server qualification.
        let conn = Connection::open(fixture.directory.path().join("authority.sqlite")).unwrap();
        assert_eq!(target_rows(&conn), retained);
        let provider = provider_lifecycle_keys();
        if action == 14 {
            let begin = fixture.request(&conn, 185, 1, 0x61, 0);
            let begin = fixture.rebind_at(&conn, begin, 100);
            assert!(matches!(
                fixture.submit(&conn, &begin),
                AuditOperationState::TargetV1(_)
            ));
            fixture.settle(&conn, &begin);
        }
        let now = if action == 12 { deadline } else { 100 };
        let resolution = if action == 10 {
            fixture.resolve_fixture(&conn, 184, 10, false, now)
        } else {
            provider_rollback(&fixture, &conn, &provider, action, now, original_config).await
        };
        let result = fixture.submit_at(&conn, &resolution, now);
        assert!(
            matches!(result, AuditOperationState::TargetV1(ref r) if
            (action == 10 && matches!(r.outcome(), NetconfAppliedOutcome::Confirmed { .. })) ||
            (action != 10 && matches!(r.outcome(), NetconfAppliedOutcome::RolledBack { running_version: 3, .. }))),
            "provider copy resolution did not preserve its exact applied outcome"
        );
        if action == 10 {
            provider_assert_history(&conn, &provider, 2, 183, tentative_config).await;
        } else {
            provider_assert_history(&conn, &provider, 3, 184, original_config).await;
        }
        fixture.assert_no_pending(&conn);
        fixture.settle(&conn, &resolution);
    }
}

#[tokio::test]
async fn target_provider_lifecycle_recovers_admitted_copy_without_repeating_provider_preparation() {
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let config = br#"{"enabled":true}"#;
    let (provider, source) = copy_provider_stage(&fixture, &conn, 0, config).await;
    let prepared = copy_provider_destination(&fixture, &conn, &provider, 0, 181, config).await;
    let prepared = bind_copy_provider(&fixture, &conn, &provider, &source, prepared)
        .await
        .unwrap();
    let encoded = prepared.encode().unwrap();
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Admit(prepared.clone()))),
            100,
        )
        .unwrap();
    fixture.checkpoint(&conn);
    let candidate = row(&conn, "config_netconf_targets", "target", 0);
    drop(prepared);
    drop(provider);
    drop(conn);
    let conn = Connection::open(fixture.directory.path().join("authority.sqlite")).unwrap();
    let original = PreparedTargetMutation::decode(&encoded).unwrap();
    original.verify_effect(&fixture.key).unwrap();
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(original.clone()))),
            100,
        )
        .unwrap();
    let outcome = fixture
        .ledger(&conn)
        .lookup(&fixture.key, original.handle(), original.effect.caller)
        .unwrap()
        .unwrap();
    assert!(matches!(outcome.state(), AuditOperationState::TargetV1(r)
        if matches!(r.outcome(), NetconfAppliedOutcome::CopiedRunning { running_version: 1 })));
    assert_eq!(row(&conn, "config_netconf_targets", "target", 0), candidate);
    fixture.settle(&conn, &original);
    let provider = provider_lifecycle_keys();
    provider_assert_history(&conn, &provider, 1, 181, config).await;
    // Replaying that exact original after its deadline does not append again.
    fixture
        .apply(
            &conn,
            AuditCommand::NetconfTarget(Box::new(TargetAuditCommandV1::Apply(original))),
            200,
        )
        .unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM config_history", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn target_provider_copy_preparation_accepts_exact_protocol_replace_operation() {
    use crate::audit_authority::NetconfLockDatastore;
    use crate::consensus::audit_mutation::TargetPayloadV1;
    let fixture = Fixture::new().await;
    let shared = fixture.backend.conn();
    let conn = shared.lock().await;
    fixture.active(&conn);
    let config = br#"{"enabled":true}"#;
    let (provider, _) = copy_provider_stage(&fixture, &conn, 0, config).await;
    let original = copy_provider_destination(&fixture, &conn, &provider, 0, 181, config).await;
    let Some(TargetPayloadV1::Running { commit, .. }) = original.effect.encrypted_payload else {
        panic!("protocol copy fixture");
    };
    let tx = conn.unchecked_transaction().unwrap();
    let view = crate::consensus::audit_targets::read_copy_view_sync(
        &tx,
        &fixture.key,
        &fixture.ledger(&tx),
        NetconfLockDatastore::Candidate,
        &crate::consensus::sqlite::SqliteWorkCancellation::audit_test(),
    )
    .unwrap()
    .unwrap();
    tx.commit().unwrap();
    let worker = std::sync::Arc::new(());
    let session = fixture.session_owner(&conn, &worker, 0x61);
    // NETCONF's copy-config handler uses Replace for its required Intent and
    // both terminal paths. Preserve that operation through SDK preparation.
    let mut protocol = fixture.event(181);
    protocol.operation = ManagementAuditOperationCode::Replace;
    let before = target_rows(&conn);
    let candidate_before = row(&conn, "config_netconf_targets", "target", 0);
    let sequence = fixture.ledger(&conn).sequence;
    let effect = view.prepare(&session, &protocol, (*commit).clone(), 160);
    assert_eq!(target_rows(&conn), before);
    assert_eq!(fixture.ledger(&conn).sequence, sequence);
    let mut effect = effect.expect("NETCONF Replace intent refused by copy preparation");
    for wrong in [
        ManagementAuditOperationCode::Exec,
        ManagementAuditOperationCode::Read,
        ManagementAuditOperationCode::Update,
        ManagementAuditOperationCode::Delete,
    ] {
        let mut event = protocol.clone();
        event.operation = wrong;
        assert!(
            matches!(
                view.prepare(&session, &event, (*commit).clone(), 160),
                Err(AuditAuthorityError::BindingMismatch)
            ),
            "copy preparation accepted another protocol operation"
        );
    }
    let mut internal = protocol.clone();
    internal.transport = ManagementAuditTransportCode::Internal;
    assert!(view.prepare(&session, &internal, *commit, 160).is_err());
    effect
        .bind_provider_copy(&provider, &view.blob)
        .await
        .unwrap();
    let prepared = fixture.rebind_at(&conn, fixture.prepare(effect, protocol), 100);
    assert_eq!(
        prepared.handle.body.event.operation,
        ManagementAuditOperationCode::Replace
    );
    assert!(
        matches!(fixture.submit(&conn, &prepared), AuditOperationState::TargetV1(r)
        if matches!(r.outcome(), NetconfAppliedOutcome::CopiedRunning { running_version: 1 }))
    );
    assert_eq!(
        row(&conn, "config_netconf_targets", "target", 0),
        candidate_before
    );
    fixture.settle(&conn, &prepared);
    provider_assert_history(&conn, &provider, 1, 181, config).await;
}
