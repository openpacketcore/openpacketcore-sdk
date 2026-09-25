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
