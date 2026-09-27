//! Real retained SQL rollback and replay after an audited ledger reservation
//! fails. These call the native log/apply primitives, not a running Raft core.
//! They do not qualify storage-error task shutdown or quorum recovery.

use super::*;
use crate::audit_authority::continuity::checkpoint::CheckpointBody;
use crate::audit_authority::continuity::{
    AuditCheckpoint, AuditKeyRing, AuditKeyTransition, AuditSigningKey,
};
use crate::audit_authority::ledger::{allocation_probe::FailureGuard, HandleBody, LedgerState};
use crate::audit_authority::{
    AuditCaller, AuditLedgerLimits, AuditOperationBinding, AuditOperationHandle,
    AuditOperationState, AuditPrivacyKey, AuditPrivacyProjection, AuditPrivacyPurpose,
    PreparedAuditedMutation, ProjectedAuditEvent,
};
use crate::consensus::audit::AuditCommand;
use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::capacity_record::CapacityRecordBinding;
use crate::consensus::{
    ConfigConsensusClusterId, ConfigConsensusCommand, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusRequestId, ConfigConsensusTopology,
    PreparedConfigCommit,
};
use crate::{
    AttestedConfigCommit, CommitRecord, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions,
};
use opc_consensus::engine::{CommittedLeaderId, Membership};
use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};
use std::cell::RefCell;

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

#[derive(Clone, Copy, Debug)]
struct ReleasedEffect {
    releases: usize,
    history: u64,
    capacity_records: u64,
    request_outcomes: u64,
    total_outcomes: u64,
    applied_index: u64,
    machine_sequence: u64,
    ledger_mac: [u8; 32],
    outer_transaction_open: bool,
}

struct ActiveFault {
    request: ConfigConsensusRequestId,
    after: usize,
    observed: ReleasedEffect,
    fault: Option<FailureGuard>,
}

thread_local! {
    static ACTIVE: RefCell<Option<ActiveFault>> = const { RefCell::new(None) };
}

struct ReleasedEffectGuard;

impl ReleasedEffectGuard {
    fn start(request: ConfigConsensusRequestId, after: usize) -> Self {
        ACTIVE.with(|slot| {
            let mut slot = slot.borrow_mut();
            assert!(slot.is_none(), "no nested native fault observation");
            *slot = Some(ActiveFault {
                request,
                after,
                observed: ReleasedEffect {
                    releases: 0,
                    history: 0,
                    capacity_records: 0,
                    request_outcomes: 0,
                    total_outcomes: 0,
                    applied_index: 0,
                    machine_sequence: 0,
                    ledger_mac: [0; 32],
                    outer_transaction_open: false,
                },
                fault: None,
            });
        });
        Self
    }

    fn observed(&self) -> ReleasedEffect {
        ACTIVE.with(|slot| {
            slot.borrow()
                .as_ref()
                .expect("active native fault")
                .observed
        })
    }

    fn injected(&self) -> bool {
        ACTIVE.with(|slot| {
            slot.borrow()
                .as_ref()
                .expect("active native fault")
                .fault
                .as_ref()
                .is_some_and(FailureGuard::injected)
        })
    }
}

impl Drop for ReleasedEffectGuard {
    fn drop(&mut self) {
        // Drop the actual probe after releasing our RefCell borrow. Both
        // thread-local scopes end even when a fixture assertion panics.
        let active = ACTIVE.with(|slot| slot.borrow_mut().take());
        drop(active);
    }
}

// Observe the actual inner savepoint release, then arm the existing real
// try_reserve_exact probe for this request only. This does not return an error,
// mutate SQL, own a ledger, or synthesize a response. There is no await while
// the guard is live; the preceding command in the same batch remains unfaulted.
pub(super) fn effect_released(conn: &Connection, request: ConfigConsensusRequestId) {
    ACTIVE.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(active) = slot.as_mut().filter(|value| value.request == request) else {
            return;
        };
        let observed = &mut active.observed;
        observed.releases += 1;
        observed.history = count(conn, "config_history");
        observed.capacity_records = count(conn, "config_raft_capacity_records");
        observed.request_outcomes = conn
            .query_row(
                "SELECT COUNT(*) FROM config_raft_request_outcomes WHERE request_id=?1",
                [request.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("actual measured request outcome count");
        observed.total_outcomes = count(conn, "config_raft_request_outcomes");
        observed.applied_index = conn
            .query_row(
                "SELECT log_index FROM config_raft_applied WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .expect("already written prefix frontier");
        observed.machine_sequence = conn
            .query_row(
                "SELECT application_sequence FROM config_raft_machine WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .expect("already written prefix sequence");
        observed.ledger_mac = ledger_mac(conn);
        observed.outer_transaction_open = !conn.is_autocommit();
        assert!(active.fault.is_none(), "selected effect releases once");
        active.fault = Some(FailureGuard::start(active.after));
    });
}

struct Fixture {
    options: RetainedConfigOptions,
    topology: ConfigConsensusTopology,
    key: AuditKey,
    keys: AuditKeyRing,
    privacy: AuditPrivacyKey,
    _root: tempfile::TempDir,
}

struct MutationWitness {
    prepared: PreparedAuditedMutation,
    caller: AuditCaller,
    encryption_key: KeyHandle,
    aad: EnvelopeAad,
    plaintext: Vec<u8>,
}

fn now() -> Timestamp {
    Timestamp::from_str("1970-01-01T00:01:40Z").expect("synthetic logical time")
}

async fn fixture() -> (Fixture, SqliteBackend) {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-capacity-ledger-fault-")
        .tempdir_in(scratch)
        .expect("private retained fixture");
    let fs = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(root.path())
        .output()
        .expect("filesystem detector");
    assert!(fs.status.success());
    let fs = std::str::from_utf8(&fs.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!fs.is_empty() && !matches!(fs, "tmpfs" | "ramfs"));
    let identity = ConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xB1; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xB2; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let node = ConsensusNodeId::new(1).expect("synthetic voter");
    let topology =
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).expect("topology");
    let binding = RetainedConfigBinding::new(topology.clone(), [0xB3; 32], [0xB4; 32])
        .expect("binding")
        .with_capacity_profile(PROFILE);
    let options = RetainedConfigOptions::new(
        root.path().join("config.sqlite"),
        binding,
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("unchanged retained limits");
    let key = AuditKey::new([0xB5; 32]).expect("synthetic root key");
    let backend = SqliteBackend::provision_config_authority(options.clone(), key.clone())
        .await
        .expect("native retained authority");
    let keys = AuditKeyRing::new(vec![
        AuditSigningKey::new(1, [0xB6; 32]).expect("separate initial signing key"),
        AuditSigningKey::new(2, [0xBE; 32]).expect("separate successor signing key"),
    ])
    .expect("retained signing ring");
    let fixture = Fixture {
        options,
        topology,
        key,
        keys,
        privacy: AuditPrivacyKey::new([0xB7; 32]).expect("separate projection key"),
        _root: root,
    };
    {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert!(crate::schema::verify_wal_mode(&conn).expect("native WAL"));
        assert!(crate::schema::verify_synchronous_extra(&conn).expect("native Durable"));
    }
    (fixture, backend)
}

fn mutation(fixture: &Fixture) -> MutationWitness {
    let tx_id = TxId::from_uuid(uuid::Uuid::from_u128(0xB800));
    let principal = "spiffe://qualification.invalid/tenant/test/ns/test/sa/config";
    let schema_digest = SchemaDigest::from_bytes([0xB9; 32]);
    let aad = EnvelopeAad::config(
        TenantId::from_static("test"),
        1,
        ConfigAad::new(tx_id, None, now(), principal, schema_digest, "running")
            .expect("synthetic AAD"),
    );
    let encryption_key = KeyHandle::new(
        KeyId::new("ledger-fault-fixture").expect("synthetic key ID"),
        KeyPurpose::Config,
        TenantId::from_static("test"),
        Zeroizing::new([0xBA; 32]),
    );
    let plaintext = br#"{"fixture":{"enabled":true}}"#.to_vec();
    let envelope = opc_crypto::encrypt_bounded_config_envelope_with_handle_and_nonce(
        &encryption_key,
        &aad,
        &plaintext,
        [0xBB; 12],
    )
    .expect("genuine bounded encryption");
    let attested = AttestedConfigCommit::try_new(
        CommitRecord {
            tx_id,
            parent_tx_id: None,
            version: ConfigVersion::new(1),
            committed_at: now(),
            principal: principal.to_owned(),
            source: CommitSource::Gnmi,
            schema_digest,
            plaintext_digest: Sha256::digest(&plaintext).to_vec(),
            encrypted_blob: envelope.encoded().to_vec(),
            rollback_point: false,
            confirmed_deadline: None,
        },
        Vec::new(),
        envelope.claim().expect("paired encryption claim"),
    )
    .expect("real attested record");
    let binding = CapacityRecordBinding::issue(
        &attested,
        fixture.topology.identity(),
        &fixture.key,
        PROFILE,
    )
    .expect("exact identity/profile binding");
    let (record, audit, _) = attested.into_parts();
    let effect = AuditedConfigEffect::BoundedAppend {
        commit: Box::new(
            PreparedConfigCommit::prepare_for_profile(record, audit, &fixture.key, PROFILE)
                .expect("genuine SDK preparation"),
        ),
        binding,
        resolution: None,
    };
    let digest = effect.digest(&fixture.key).expect("exact immutable effect");
    let event = crate::ManagementAuditEventRecord::try_new(
        [0xBC; 16],
        crate::ManagementAuditInstant::try_new(
            100,
            0,
            1,
            crate::ManagementAuditTimeSourceCode::NodeClock,
        )
        .expect("synthetic source time"),
        "test",
        principal,
        crate::ManagementAuditTransportCode::Gnmi,
        crate::ManagementAuditOperationCode::Update,
        crate::ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:configuration"],
        Some(tx_id.to_string()),
    )
    .expect("bounded source event");
    let projected =
        ProjectedAuditEvent::project(&fixture.privacy, &event).expect("real projection");
    let binding = AuditOperationBinding::project(&fixture.privacy, &projected, 0, &digest)
        .expect("original effect and caller binding");
    let caller = projected.caller;
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: fixture.topology.identity(),
            binding,
            event: projected,
            issued_at: 100,
            expires_at: 160,
            nonce: [0xBD; 16],
            key_epoch: fixture.key.epoch(),
            mutation: Some(digest),
        },
        &fixture.key,
    )
    .expect("authenticate the original operation");
    MutationWitness {
        // Component construction below the public submission pool. The native
        // receiver verifies the actual command and proof before WAL/apply.
        prepared: PreparedAuditedMutation::new(handle, effect, None),
        caller,
        encryption_key,
        aad,
        plaintext,
    }
}

fn log_id(fixture: &Fixture, index: u64) -> LogId<ConsensusNodeId> {
    LogId::new(
        CommittedLeaderId::new(1, fixture.topology.local_node_id()),
        index,
    )
}

fn entry(
    fixture: &Fixture,
    index: u64,
    intent: ConfigMutationIntent,
) -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: log_id(fixture, index),
        payload: EntryPayload::Normal(ConfigConsensusCommand {
            schema_version: 8,
            identity: fixture.topology.identity(),
            request_id: ConfigConsensusRequestId::from_bytes(
                [u8::try_from(index).expect("fixture request ordinal"); 16],
            ),
            logical_time: now(),
            intent,
        }),
    }
}

fn audit_entry(
    fixture: &Fixture,
    index: u64,
    command: AuditCommand,
) -> Entry<ConfigRaftTypeConfig> {
    entry(
        fixture,
        index,
        ConfigMutationIntent::ManagementAudit(Box::new(command)),
    )
}

fn append_batch_committed(
    conn: &Connection,
    fixture: &Fixture,
    entries: &[Entry<ConfigRaftTypeConfig>],
) {
    validate_entry_capacities(
        entries,
        fixture.topology.identity(),
        &fixture.key,
        super::RetainedConfigMode::BoundedV1,
    )
    .expect("real pre-WAL admission");
    append_logs_sync(
        conn,
        fixture.topology.identity(),
        fixture.topology.members(),
        entries,
        super::RetainedConfigMode::BoundedV1,
    )
    .expect("native durable log append");
    save_committed_sync(
        conn,
        fixture.topology.identity(),
        entries.last().map(|entry| entry.log_id),
        super::RetainedConfigMode::BoundedV1,
    )
    .expect("native committed prefix");
}

fn append_committed(conn: &Connection, fixture: &Fixture, entry: Entry<ConfigRaftTypeConfig>) {
    append_batch_committed(conn, fixture, &[entry]);
}

fn read_entry(conn: &Connection, fixture: &Fixture, index: u64) -> Entry<ConfigRaftTypeConfig> {
    let mut entries = read_log_range_sync(
        conn,
        fixture.topology.identity(),
        fixture.topology.members(),
        index,
        Some(index + 1),
        Some(1),
        super::RetainedConfigMode::BoundedV1,
    )
    .expect("actual native saved-byte decode");
    assert_eq!(entries.len(), 1, "one original stored entry");
    entries.remove(0)
}

fn saved_bytes(conn: &Connection, index: u64) -> Vec<u8> {
    conn.query_row(
        "SELECT entry_json FROM config_raft_log WHERE log_index=?1",
        [i64::try_from(index).expect("fixture log index")],
        |row| row.get(0),
    )
    .expect("exact durable entry bytes")
}

fn apply_saved_batch(
    conn: &Connection,
    fixture: &Fixture,
    first: u64,
    count: usize,
) -> io::Result<Vec<ConfigConsensusResponse>> {
    let entries = read_log_range_sync(
        conn,
        fixture.topology.identity(),
        fixture.topology.members(),
        first,
        Some(first + u64::try_from(count).expect("fixture range")),
        Some(count),
        super::RetainedConfigMode::BoundedV1,
    )?;
    assert_eq!(entries.len(), count, "all exact original saved entries");
    let responses = apply_entries_cancellable_sync(
        conn,
        fixture.topology.identity(),
        fixture.topology.members(),
        entries,
        &SqliteWorkCancellation::new(),
        &fixture.key,
        Some(&fixture.keys),
        super::RetainedConfigMode::BoundedV1,
    )?;
    assert_eq!(responses.len(), count, "one actual response per entry");
    Ok(responses)
}

fn apply_saved(
    conn: &Connection,
    fixture: &Fixture,
    index: u64,
) -> io::Result<ConfigConsensusResponse> {
    Ok(apply_saved_batch(conn, fixture, index, 1)?.remove(0))
}

fn append_apply(conn: &Connection, fixture: &Fixture, entry: Entry<ConfigRaftTypeConfig>) {
    let index = entry.log_id.index;
    append_committed(conn, fixture, entry);
    assert_eq!(
        apply_saved(conn, fixture, index)
            .expect("native apply")
            .result,
        Ok(())
    );
}

fn ledger(conn: &Connection, fixture: &Fixture) -> LedgerState {
    crate::consensus::audit::read_with_keys_sync(
        conn,
        &fixture.key,
        Some(&fixture.keys),
        fixture.topology.identity(),
    )
    .expect("root MAC, exact identity and full continuity verification")
    .expect("active ledger")
}

fn checkpoint(conn: &Connection, fixture: &Fixture, index: u64) {
    let ledger = ledger(conn, fixture);
    let chain = ledger.continuity.as_ref().expect("signed prefix");
    // Component checkpoint setup authenticates the exact real prefix. This is
    // not an external checkpoint port or rollback-authority runtime test.
    let checkpoint = AuditCheckpoint::issue(
        &fixture.keys,
        CheckpointBody {
            version: 1,
            identity: ledger.identity,
            sequence: ledger.sequence,
            root_anchor: ledger.terminal,
            anchor: chain.terminal,
            epoch_at_sequence: chain.active_epoch,
            signing_epoch: chain.active_epoch,
            acknowledged_export: [0; 32],
        },
    )
    .expect("authenticate the current exact checkpoint");
    append_apply(
        conn,
        fixture,
        audit_entry(fixture, index, AuditCommand::Checkpoint(checkpoint)),
    );
}

fn count(conn: &Connection, table: &str) -> u64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .expect("authoritative row count")
}

fn ledger_mac(conn: &Connection) -> [u8; 32] {
    let mac: Vec<u8> = conn
        .query_row(
            "SELECT state_hmac FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .expect("actual stored ledger authenticator");
    mac.try_into()
        .expect("fixed-width stored ledger authenticator")
}

fn authority_image(conn: &Connection) -> Vec<(&'static str, [u8; 32])> {
    use rusqlite::types::ValueRef;

    [
        "config_history",
        "audit_trail",
        "config_lifecycle_audit",
        "rollback_labels",
        "config_raft_identity",
        "config_raft_vote",
        "config_raft_log",
        "config_raft_applied",
        "config_raft_committed",
        "config_raft_purged",
        "config_raft_machine",
        "config_raft_membership",
        "config_raft_request_outcomes",
        "config_raft_snapshot",
        "config_raft_management_audit",
        "config_raft_history_retention",
        "config_raft_capacity_records",
        "consensus_retained_binding",
    ]
    .into_iter()
    .map(|table| {
        let mut digest = Sha256::new();
        digest.update(table.as_bytes());
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .expect("complete authoritative table");
        let columns = statement.column_count();
        let mut rows = statement.query([]).expect("authoritative rows");
        while let Some(row) = rows.next().expect("authoritative row") {
            digest.update([0xFF]);
            for column in 0..columns {
                match row.get_ref(column).expect("authoritative value") {
                    ValueRef::Null => digest.update([0]),
                    ValueRef::Integer(value) => {
                        digest.update([1]);
                        digest.update(value.to_be_bytes());
                    }
                    ValueRef::Real(value) => {
                        digest.update([2]);
                        digest.update(value.to_bits().to_be_bytes());
                    }
                    ValueRef::Text(value) => {
                        digest.update([3]);
                        digest.update((value.len() as u64).to_be_bytes());
                        digest.update(value);
                    }
                    ValueRef::Blob(value) => {
                        digest.update([4]);
                        digest.update((value.len() as u64).to_be_bytes());
                        digest.update(value);
                    }
                }
            }
        }
        (table, digest.finalize().into())
    })
    .collect()
}

fn effect_image(conn: &Connection) -> Vec<(&'static str, [u8; 32])> {
    authority_image(conn)
        .into_iter()
        .filter(|(table, _)| {
            !matches!(
                *table,
                "config_raft_log" | "config_raft_committed" | "config_raft_applied"
            )
        })
        .collect()
}

fn assert_original_receipt(
    conn: &Connection,
    fixture: &Fixture,
    witness: &MutationWitness,
    state: AuditOperationState,
    terminal: bool,
) {
    let ledger = ledger(conn, fixture);
    let receipt = ledger
        .lookup(&fixture.key, witness.prepared.handle(), witness.caller)
        .expect("authenticate original handle and caller")
        .expect("original operation retained");
    assert_eq!(receipt.handle(), witness.prepared.handle());
    assert_eq!(receipt.state(), state);
    assert_eq!(receipt.terminal_recorded(), terminal);
    assert_eq!(
        ledger.operations.len(),
        1,
        "never mint a replacement operation"
    );
}

fn assert_readback(conn: &Connection, fixture: &Fixture, witness: &MutationWitness) {
    validate_sealed_state_for_profile_sync(
        conn,
        fixture.topology.identity(),
        &fixture.key,
        super::RetainedConfigMode::BoundedV1,
        &SqliteWorkCancellation::new(),
    )
    .expect("full authenticated sealed history and capacity proof");
    let AuditedConfigEffect::BoundedAppend { commit, .. } = &witness.prepared.command().effect
    else {
        panic!("bounded append witness");
    };
    let actual = SqliteBackend::load_by_tx_id_bytes(
        conn,
        commit.record.tx_id.as_uuid().as_bytes(),
        &fixture.key,
    )
    .expect("actual SDK authenticated readback")
    .expect("original configuration");
    assert!(
        actual.record == commit.record,
        "exact original retained record"
    );
    assert!(
        actual.audit == commit.audit,
        "exact original audit metadata"
    );
    let plaintext = opc_crypto::decrypt_envelope_with_handle(
        &witness.encryption_key,
        &witness.aad,
        &actual.record.encrypted_blob,
    )
    .expect("authenticate actual retained ciphertext");
    assert_eq!(plaintext.as_slice(), witness.plaintext.as_slice());
    assert_eq!(count(conn, "config_history"), 1, "one configuration effect");
    assert_eq!(
        count(conn, "config_raft_capacity_records"),
        1,
        "one bound proof"
    );
}

fn assert_stored_outcome(
    conn: &Connection,
    fixture: &Fixture,
    command: &ConfigConsensusCommand,
    response: &ConfigConsensusResponse,
) {
    let (digest, stored) = read_outcome_sync(
        conn,
        fixture.topology.identity(),
        &fixture.key,
        super::RetainedConfigMode::BoundedV1,
        command.request_id,
    )
    .expect("authenticated identity/profile-bound stored outcome")
    .expect("original request outcome");
    assert_eq!(
        digest,
        command.payload_digest().expect("original payload digest")
    );
    assert_eq!(
        &stored, response,
        "original authenticated response survives recovery"
    );
}

async fn reservation_fault(after: usize) {
    let (fixture, backend) = fixture().await;
    let witness = mutation(&fixture);
    let original = entry(
        &fixture,
        5,
        ConfigMutationIntent::AuditedMutation(witness.prepared.command().clone()),
    );
    let EntryPayload::Normal(command) = &original.payload else {
        panic!("original command")
    };
    let command = command.clone();
    let identity = fixture.topology.identity();
    let (before, original_bytes, previous_machine) = {
        let shared = backend.conn();
        let conn = shared.lock().await;
        append_apply(
            &conn,
            &fixture,
            Entry {
                log_id: log_id(&fixture, 0),
                payload: EntryPayload::Membership(Membership::new(
                    vec![fixture.topology.members().clone()],
                    fixture.topology.members().clone(),
                )),
            },
        );
        append_apply(
            &conn,
            &fixture,
            audit_entry(
                &fixture,
                1,
                AuditCommand::InitializeWithContinuity {
                    projection: fixture
                        .privacy
                        .project(AuditPrivacyPurpose::KeyIdentity, &[])
                        .expect("admitted projection"),
                    limits: AuditLedgerLimits::new(4096, 1024).expect("unchanged limits"),
                    initial_epoch: 1,
                },
            ),
        );
        append_apply(
            &conn,
            &fixture,
            audit_entry(
                &fixture,
                2,
                AuditCommand::Intent(witness.prepared.handle().clone()),
            ),
        );
        checkpoint(&conn, &fixture, 3);
        assert_original_receipt(
            &conn,
            &fixture,
            &witness,
            AuditOperationState::Intent,
            false,
        );
        let prefix = ledger(&conn, &fixture);
        let chain = prefix.continuity.as_ref().expect("signed original Intent");
        assert_eq!((prefix.entries.len(), chain.rows.len()), (1, 1));
        assert_eq!(
            prefix.entries.capacity(),
            prefix.entries.len(),
            "exact decoded entry owner"
        );
        assert_eq!(
            chain.rows.capacity(),
            chain.rows.len(),
            "exact decoded signed-row owner"
        );
        // The first entry in the failed batch really changes the authenticated
        // ledger, writes a request outcome and advances the applied frontier.
        // Their rollback must be observed, not inferred from still-absent rows.
        let transition = AuditKeyTransition::prepare(
            &fixture.keys,
            identity,
            prefix.sequence,
            chain.terminal,
            chain.active_epoch,
            2,
        )
        .expect("cross-authenticate the exact original key transition");
        drop(prefix);
        let preceding = audit_entry(&fixture, 4, AuditCommand::Transition(transition));
        append_batch_committed(&conn, &fixture, &[preceding, original]);
        assert_eq!(
            read_applied_sync(&conn, identity).expect("applied prefix"),
            Some(log_id(&fixture, 3))
        );
        assert_eq!(
            read_committed_sync(&conn, identity).expect("committed original batch"),
            Some(log_id(&fixture, 5))
        );
        let before = authority_image(&conn);
        let original_bytes = [saved_bytes(&conn, 4), saved_bytes(&conn, 5)];
        let previous_machine = read_machine_sync(&conn, identity).expect("preceding machine state");
        let previous_ledger_mac = ledger_mac(&conn);
        assert_eq!(count(&conn, "config_raft_request_outcomes"), 3);

        // No await inside the thread-local scope. The hook arms the existing
        // probe only after this request's actual inner savepoint releases.
        // The native allocator call itself returns the TryReserveError.
        let fault = ReleasedEffectGuard::start(command.request_id, after);
        let error = apply_saved_batch(&conn, &fixture, 4, 2)
            .expect_err("reservation failure is storage I/O");
        assert!(
            fault.injected(),
            "NATIVE_LEDGER_FAULT_ACTUAL_TRY_RESERVE_ERROR"
        );
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "existing audited apply I/O mapping"
        );
        let released = fault.observed();
        drop(fault);
        assert_eq!(
            released.releases, 1,
            "NATIVE_LEDGER_FAULT_AFTER_INNER_RELEASE"
        );
        assert_eq!(
            (
                released.history,
                released.capacity_records,
                released.request_outcomes
            ),
            (1, 1, 0),
            "NATIVE_LEDGER_FAULT_REAL_EFFECT_BEFORE_ERROR"
        );
        assert_eq!(
            (
                released.total_outcomes,
                released.applied_index,
                released.machine_sequence
            ),
            (4, 4, previous_machine.0 + 1),
            "NATIVE_LEDGER_FAULT_PREFIX_METADATA_WAS_WRITTEN"
        );
        assert_ne!(
            released.ledger_mac, previous_ledger_mac,
            "NATIVE_LEDGER_FAULT_PREFIX_LEDGER_WAS_WRITTEN"
        );
        assert!(
            released.outer_transaction_open,
            "outer transaction owns the released effect and preceding entry"
        );
        assert!(
            conn.is_autocommit(),
            "failed apply releases its transaction"
        );
        eprintln!(
            "NATIVE_LEDGER_FAULT_INJECTED after={after} history=1 proof=1 prefix_outcome=1 applied=4 ledger_changed=true"
        );
        assert_eq!(
            authority_image(&conn),
            before,
            "NATIVE_LEDGER_FAULT_OUTER_ROLLBACK"
        );
        assert_original_receipt(
            &conn,
            &fixture,
            &witness,
            AuditOperationState::Intent,
            false,
        );
        assert_eq!(
            read_applied_sync(&conn, identity).expect("rolled-back applied prefix"),
            Some(log_id(&fixture, 3))
        );
        assert_eq!(
            read_committed_sync(&conn, identity).expect("unchanged committed batch"),
            Some(log_id(&fixture, 5))
        );
        assert_eq!(
            read_machine_sync(&conn, identity).expect("rolled-back machine"),
            previous_machine
        );
        for request in [
            ConfigConsensusRequestId::from_bytes([4; 16]),
            command.request_id,
        ] {
            assert!(read_outcome_sync(
                &conn,
                identity,
                &fixture.key,
                super::RetainedConfigMode::BoundedV1,
                request
            )
            .expect("authenticated absent outcome")
            .is_none());
        }
        validate_sealed_state_for_profile_sync(
            &conn,
            identity,
            &fixture.key,
            super::RetainedConfigMode::BoundedV1,
            &SqliteWorkCancellation::new(),
        )
        .expect("authenticated rollback state");
        (before, original_bytes, previous_machine)
    };

    // Drop every connection owner before reacquiring the retained file binding.
    drop(backend);
    let backend =
        SqliteBackend::reopen_config_authority(fixture.options.clone(), fixture.key.clone())
            .await
            .expect("full retained reopen with committed but unapplied original batch");
    let response = {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert!(crate::schema::verify_wal_mode(&conn).expect("reopened WAL"));
        assert!(crate::schema::verify_synchronous_extra(&conn).expect("reopened Durable"));
        assert_eq!(
            authority_image(&conn),
            before,
            "NATIVE_LEDGER_FAULT_REOPENED_ROLLBACK"
        );
        assert_eq!(
            [saved_bytes(&conn, 4), saved_bytes(&conn, 5)],
            original_bytes,
            "original committed batch bytes retained"
        );
        assert_original_receipt(
            &conn,
            &fixture,
            &witness,
            AuditOperationState::Intent,
            false,
        );
        let mut responses = apply_saved_batch(&conn, &fixture, 4, 2)
            .expect("replay original batch without the scoped fault");
        assert_eq!(responses[0].result, Ok(()), "original transition replayed");
        let response = responses.remove(1);
        assert_eq!(
            response.result,
            Ok(()),
            "NATIVE_LEDGER_FAULT_ORIGINAL_REPLAY_APPLIED"
        );
        assert_eq!(response.sequence, previous_machine.0 + 2);
        assert_eq!(response.raft_log_index, 5);
        let receipt = response
            .audit_receipt
            .as_ref()
            .expect("actual applied receipt")
            .read_back(
                &fixture.key,
                identity,
                witness.prepared.handle(),
                witness.caller,
            )
            .expect("authenticate original applied receipt");
        assert_eq!(receipt.handle(), witness.prepared.handle());
        assert_eq!(
            receipt.state(),
            AuditOperationState::Committed { version: 1 }
        );
        assert!(
            !receipt.terminal_recorded(),
            "terminal has not been supplied"
        );
        assert_original_receipt(
            &conn,
            &fixture,
            &witness,
            AuditOperationState::Committed { version: 1 },
            false,
        );
        assert_readback(&conn, &fixture, &witness);
        assert_stored_outcome(&conn, &fixture, &command, &response);
        assert_eq!(
            read_applied_sync(&conn, identity).expect("replayed frontier"),
            Some(log_id(&fixture, 5))
        );
        assert_eq!(
            ledger(&conn, &fixture)
                .continuity
                .as_ref()
                .expect("retained signing chain")
                .active_epoch,
            2,
            "original cross-authenticated transition retained"
        );
        let once = effect_image(&conn);
        let once_machine = read_machine_sync(&conn, identity).expect("once-applied machine");
        let mut retry = read_entry(&conn, &fixture, 5);
        retry.log_id = log_id(&fixture, 6);
        // A later log position retries exactly the same request/effect/handle.
        // Reusing log index 5 would only test the contiguous-apply guard.
        append_committed(&conn, &fixture, retry);
        assert_eq!(
            apply_saved(&conn, &fixture, 6).expect("native original-request dedup"),
            response,
            "NATIVE_LEDGER_FAULT_ORIGINAL_RESPONSE_DEDUP"
        );
        assert_eq!(
            effect_image(&conn),
            once,
            "NATIVE_LEDGER_FAULT_EXACTLY_ONCE"
        );
        assert_eq!(
            read_machine_sync(&conn, identity).expect("deduplicated machine"),
            once_machine
        );
        assert_eq!(
            read_applied_sync(&conn, identity).expect("retry frontier"),
            Some(log_id(&fixture, 6))
        );
        append_apply(
            &conn,
            &fixture,
            audit_entry(
                &fixture,
                7,
                AuditCommand::Terminal(witness.prepared.handle().clone()),
            ),
        );
        checkpoint(&conn, &fixture, 8);
        assert_original_receipt(
            &conn,
            &fixture,
            &witness,
            AuditOperationState::Committed { version: 1 },
            true,
        );
        let completed = ledger(&conn, &fixture);
        assert_eq!(
            completed.entries.len(),
            4,
            "one Intent, one transition, one outcome and one terminal"
        );
        assert_eq!(
            completed
                .continuity
                .as_ref()
                .expect("signed completion")
                .checkpoint
                .as_ref()
                .expect("covering checkpoint")
                .sequence(),
            completed.sequence
        );
        response
    };
    drop(backend);
    let backend =
        SqliteBackend::reopen_config_authority(fixture.options.clone(), fixture.key.clone())
            .await
            .expect("full retained reopen after exact original completion");
    {
        let shared = backend.conn();
        let conn = shared.lock().await;
        assert_readback(&conn, &fixture, &witness);
        assert_original_receipt(
            &conn,
            &fixture,
            &witness,
            AuditOperationState::Committed { version: 1 },
            true,
        );
        assert_stored_outcome(&conn, &fixture, &command, &response);
        assert_eq!(
            [saved_bytes(&conn, 4), saved_bytes(&conn, 5)],
            original_bytes
        );
        assert_eq!(
            read_applied_sync(&conn, identity).expect("final applied prefix"),
            Some(log_id(&fixture, 8))
        );
        assert_eq!(
            read_committed_sync(&conn, identity).expect("final committed prefix"),
            Some(log_id(&fixture, 8))
        );
    }
    drop(backend);
    eprintln!(
        "NATIVE_LEDGER_FAULT_LIFECYCLE_COMPLETE after={after} replay=original exactly_once=true"
    );
}

#[tokio::test]
async fn native_audited_entry_reservation_fault_rolls_back_and_replays() {
    reservation_fault(0).await;
}

#[tokio::test]
async fn native_audited_signed_row_reservation_fault_rolls_back_and_replays() {
    reservation_fault(1).await;
}
