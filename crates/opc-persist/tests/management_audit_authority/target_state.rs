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
