//! Retained codec and SQL-ledger component tests. Joint native opening is still
//! refused. These do not qualify native target apply, external checkpoint I/O,
//! protocol admission or a whole-operation memory envelope.

use super::*;
use crate::audit_authority::continuity::chain::ContinuityState;
use crate::audit_authority::continuity::{AuditKeyRing, AuditSigningKey};
use crate::audit_authority::ledger::{EntryPayload, LedgerState};
use crate::audit_authority::{AuditLedgerLimits, AuditOperationState};
use rusqlite::{params, Connection};

fn ledger() -> LedgerState {
    let mut ledger = LedgerState::new(
        identity(),
        event().projection,
        AuditLedgerLimits::new(6, 2).unwrap(),
    );
    ledger.continuity = Some(ContinuityState::new(1));
    ledger
}

fn keys() -> AuditKeyRing {
    AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x7c; 32]).unwrap()]).unwrap()
}

fn original(ledger: &LedgerState) -> &str {
    let EntryPayload::TargetIntent(retained) = &ledger.entries[0].payload else {
        panic!("actual retained target Intent")
    };
    &retained.recovery
}

fn replace_original(ledger: &mut LedgerState, bytes: String) {
    let EntryPayload::TargetIntent(retained) = &mut ledger.entries[0].payload else {
        panic!("actual retained target Intent")
    };
    retained.recovery = bytes;
}

fn admit(prepared: &PreparedTargetMutation) -> LedgerState {
    prepared
        .verify_bounded_running(&key(), identity(), event().caller)
        .unwrap();
    crate::consensus::store::preflight_joint_target_payload(prepared).unwrap();
    let mut state = ledger();
    assert!(
        state.admit_target(&key(), prepared.command(), 110).is_ok(),
        "TARGET_RETAINED_BOUNDED_ADMISSION"
    );
    state.seal_continuity(Some(&keys())).unwrap();
    state
        .validate(&key(), identity())
        .expect("TARGET_RETAINED_BOUNDED_VALIDATE");
    state.validate_continuity(Some(&keys())).unwrap();
    state
}

fn initialize_sql_ledger(connection: &Connection) {
    // The exact read/write codec tables only, not an admitted consensus catalog.
    // Identity comes from this independently supplied fixture, not the JSON row.
    connection
        .execute_batch(
            "CREATE TABLE config_raft_identity (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                cluster_id BLOB NOT NULL CHECK (length(cluster_id) = 32),
                configuration_id BLOB NOT NULL CHECK (length(configuration_id) = 32),
                configuration_epoch INTEGER NOT NULL CHECK (configuration_epoch > 0)
            );
            CREATE TABLE config_raft_management_audit (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                state_json BLOB NOT NULL CHECK (length(state_json) BETWEEN 1 AND 16777216),
                state_hmac BLOB NOT NULL CHECK (length(state_hmac) = 32)
            );",
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO config_raft_identity VALUES(1,?1,?2,?3)",
            params![
                identity().cluster_id().as_bytes().as_slice(),
                identity().configuration_id().as_bytes().as_slice(),
                identity().configuration_epoch().get() as i64,
            ],
        )
        .unwrap();
}

#[tokio::test]
async fn retained_target_bounded_at_limit_survives_sql_reopen() {
    let pool = ConfigPreparationPool::bounded_v1();
    let mut plaintext = vec![b'x'; opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES];
    plaintext[0] = b'"';
    *plaintext.last_mut().unwrap() = b'"';
    let prepared = signed(payload(&pool, &plaintext).await);
    let handle = prepared.handle().clone();
    let encoded = prepared.encode().unwrap();
    let ciphertext_hash = Sha256::digest(
        &prepared
            .bounded_running()
            .unwrap()
            .commit()
            .record
            .encrypted_blob,
    );
    let binding = prepared.bounded_running().unwrap().binding().encode();
    let state = admit(&prepared);
    assert_eq!(original(&state).as_bytes(), encoded);
    assert!(PreparedTargetMutation::decode(&encoded).is_err());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retained-original.db");
    let connection = Connection::open(&path).unwrap();
    initialize_sql_ledger(&connection);
    crate::consensus::audit::write_sync(&connection, &key(), identity(), Some(state), true)
        .unwrap();
    drop(prepared);
    all_slots_available(&pool);
    drop(connection);

    let connection = Connection::open(&path).unwrap();
    let mut reopened = crate::consensus::audit::read_with_keys_sync(
        &connection,
        &key(),
        Some(&keys()),
        identity(),
    )
    .unwrap()
    .unwrap();
    let decoded = reopened
        .recover_target(&key(), &handle, event().caller)
        .unwrap();
    assert_eq!(decoded.handle(), &handle, "TARGET_RETAINED_ORIGINAL_HANDLE");
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
    assert!(
        decoded.preparation.is_none(),
        "TARGET_RETAINED_NO_LOCAL_TRUST"
    );
    assert!(
        decoded.encode().is_err(),
        "TARGET_RETAINED_NO_ENCODING_AUTHORITY"
    );
    assert!(
        decoded
            .begin_submission(&pool, ConfigCapacityProfile::BoundedV1)
            .is_err(),
        "TARGET_RETAINED_NO_SUBMISSION_AUTHORITY"
    );
    let payload = decoded.bounded_running().unwrap();
    assert_eq!(payload.binding().encode(), binding);
    let record = &payload.commit().record;
    assert_eq!(Sha256::digest(&record.encrypted_blob), ciphertext_hash);
    let aad = EnvelopeAad::config(
        TenantId::from_static("synthetic"),
        record.version.get(),
        ConfigAad::new(
            record.tx_id,
            record.parent_tx_id,
            record.committed_at,
            &record.principal,
            record.schema_digest,
            "running",
        )
        .unwrap(),
    );
    let encryption_key = Provider
        .get_active_key(KeyPurpose::Config, &TenantId::from_static("synthetic"))
        .await
        .unwrap();
    assert_eq!(
        opc_crypto::decrypt_envelope_with_handle(&encryption_key, &aad, &record.encrypted_blob)
            .unwrap()
            .as_slice(),
        plaintext
    );
    // Replay is the same original, even after expiry; first admission of that
    // expired description is still refused. No new operation ID is issued.
    reopened
        .admit_target(&key(), decoded.command(), 1000)
        .unwrap();
    assert_eq!(reopened.sequence, 1);
    assert!(ledger()
        .admit_target(&key(), decoded.command(), 1000)
        .is_err());
    assert_eq!(
        reopened
            .lookup(&key(), &handle, event().caller)
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Intent
    );
    // Actual ledger primitive transitions, not a fabricated Applied result.
    reopened
        .resolve(&key(), &handle, AuditOperationState::Rejected)
        .unwrap();
    reopened
        .resolve(&key(), &handle, AuditOperationState::Rejected)
        .unwrap();
    reopened.acknowledge_terminal(&key(), &handle).unwrap();
    reopened.seal_continuity(Some(&keys())).unwrap();
    assert_eq!(reopened.sequence, 3);
    assert!(reopened.mutation_outcome_needs_checkpoint(&reopened.operations[0]));
    crate::consensus::audit::write_sync(&connection, &key(), identity(), Some(reopened), false)
        .unwrap();
    drop(connection);
    drop(decoded);
    let connection = Connection::open(&path).unwrap();
    let final_state = crate::consensus::audit::read_with_keys_sync(
        &connection,
        &key(),
        Some(&keys()),
        identity(),
    )
    .unwrap()
    .unwrap();
    let receipt = final_state
        .lookup(&key(), &handle, event().caller)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state(), AuditOperationState::Rejected);
    assert!(receipt.terminal_recorded());
    assert!(final_state.mutation_outcome_needs_checkpoint(&final_state.operations[0]));
    let final_original = final_state
        .recover_target(&key(), &handle, event().caller)
        .unwrap();
    assert_eq!(serde_json::to_vec(&final_original).unwrap(), encoded);
    eprintln!("TARGET_RETAINED_SQL_REOPEN original=true logical={} rejected=true terminal=true checkpoint_debt=true", plaintext.len());
}

#[tokio::test]
async fn retained_target_bounded_admission_requires_record_proof() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let valid = admit(&prepared);
    let mut value: serde_json::Value = serde_json::from_slice(original(&valid).as_bytes()).unwrap();
    let tag = prepared.bounded_running().unwrap().binding().encode()[12];
    value["effect"]["encrypted_payload"]["bounded-running"]["binding"]["tag"][0] = json!(tag ^ 1);
    let mut changed = input(&serde_json::to_vec(&value).unwrap());
    resign(&mut changed);
    // The original-operation MAC is valid; the separately keyed size proof is not.
    changed
        .command()
        .handle
        .verify(&key(), identity(), event().caller)
        .unwrap();
    crate::audit_authority::ledger::verify(
        &key(),
        crate::consensus::audit_mutation::TARGET_MUTATION_DOMAIN,
        &changed.command().effect,
        changed.handle().body.mutation.as_ref().unwrap(),
    )
    .unwrap();
    let mut state = ledger();
    assert!(
        state.admit_target(&key(), changed.command(), 110).is_err(),
        "TARGET_RETAINED_RECORD_PROOF"
    );
    assert_eq!(state.sequence, 0);
    assert!(state.entries.is_empty());
    assert!(state.operations.is_empty());
    let mut foreign = ledger();
    foreign.identity = ConfigConsensusIdentity::new(
        ConsensusClusterId::from_bytes([0x7d; 32]),
        identity().configuration_id(),
        identity().configuration_epoch(),
    );
    assert!(foreign
        .admit_target(&key(), prepared.command(), 110)
        .is_err());
    assert_eq!(foreign.sequence, 0);
}

#[tokio::test]
async fn retained_target_bounded_admission_requires_full_command_budget() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let valid = admit(&prepared);
    let mut changed = input(original(&valid).as_bytes());
    let Some(TargetPayloadV1::BoundedRunning(payload)) =
        &mut changed.command_mut().effect.encrypted_payload
    else {
        panic!("bounded fixture")
    };
    let fields = Arc::get_mut(&mut payload.fields).unwrap();
    let tx_id = fields.commit.record.tx_id;
    for sequence in 0..25 {
        fields.commit.audit.push(AuditRecord {
            tx_id,
            sequence,
            yang_path: format!("/{}", "x".repeat(CONFIG_AUDIT_PATH_MAX_BYTES - 1)),
            op_type: crate::AuditOpType::Replace,
            previous_value: None,
            new_value: None,
            redaction_applied: false,
            previous_hash: [0; 32],
            entry_hmac: [0; 32],
        });
    }
    resign(&mut changed);
    changed
        .verify_bounded_running(&key(), identity(), event().caller)
        .unwrap();
    assert!(crate::consensus::store::preflight_joint_target_payload(&changed).is_err());
    let mut state = ledger();
    assert!(
        state.admit_target(&key(), changed.command(), 110).is_err(),
        "TARGET_RETAINED_COMPLETE_BUDGET"
    );
    assert_eq!(state.sequence, 0);
    assert!(state.entries.is_empty());
    assert!(state.operations.is_empty());
}

#[tokio::test]
async fn retained_target_recovery_rejects_noncanonical_and_substituted_original() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let mut state = admit(&prepared);
    let saved = original(&state).to_owned();
    state
        .recover_target(&key(), prepared.handle(), event().caller)
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&saved).unwrap();
    let mut omitted = value.clone();
    omitted["effect"]
        .as_object_mut()
        .unwrap()
        .remove("resolution");
    let cases = [
        serde_json::to_string_pretty(&value).unwrap(),
        format!("{saved} "),
        saved.replace("fixture.invalid", "fixt\\u0075re.invalid"),
        saved.replacen("\"format\":1", "\"format\":1,\"format\":1", 1),
        saved.replacen("\"effect\":{", "\"effect\":{\"unknown\":0,", 1),
        serde_json::to_string(&omitted).unwrap(),
    ];
    for changed in cases {
        assert_ne!(changed, saved, "distinct noncanonical representation");
        replace_original(&mut state, changed);
        // Call the retained-original boundary directly so no outer ledger MAC
        // refusal can falsely satisfy the canonical representation detector.
        assert!(
            state
                .recover_target(&key(), prepared.handle(), event().caller)
                .is_err(),
            "TARGET_RETAINED_CANONICAL"
        );
    }
    replace_original(&mut state, saved.clone());
    state
        .recover_target(&key(), prepared.handle(), event().caller)
        .unwrap();
    let mut changed = input(saved.as_bytes());
    let mut body = changed.handle().body.clone();
    body.nonce[0] ^= 1;
    changed.command_mut().handle = AuditOperationHandle::issue(body, &key()).unwrap();
    changed
        .verify_bounded_running(&key(), identity(), event().caller)
        .unwrap();
    replace_original(
        &mut state,
        String::from_utf8(serde_json::to_vec(&changed).unwrap()).unwrap(),
    );
    assert!(
        state
            .recover_target(&key(), prepared.handle(), event().caller)
            .is_err(),
        "TARGET_RETAINED_EXACT_ORIGINAL"
    );
}

#[tokio::test]
async fn retained_target_recovery_owns_destination_and_preserves_original_scope() {
    let source = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&source, b"null").await);
    let handle = prepared.handle().clone();
    let state = admit(&prepared);
    drop(prepared);
    all_slots_available(&source);
    let unowned = state
        .recover_target(&key(), &handle, event().caller)
        .unwrap();
    assert!(
        unowned.preparation.is_none(),
        "TARGET_RETAINED_NO_LOCAL_TRUST"
    );
    let destination = ConfigPreparationPool::bounded_v1();
    let other: Vec<_> = (0..7).map(|_| destination.try_reserve().unwrap()).collect();
    let restored = recover(
        original(&state).as_bytes(),
        destination.try_reserve().unwrap(),
        &destination,
        identity(),
        &key(),
        event().caller,
    )
    .unwrap();
    assert_eq!(restored, unowned);
    assert_eq!(restored.handle(), &handle);
    assert!(
        destination.try_reserve().is_err(),
        "TARGET_RETAINED_RECOVERY_OWNER"
    );
    let alias = restored.clone();
    let submission = restored
        .begin_submission(&destination, ConfigCapacityProfile::BoundedV1)
        .unwrap();
    assert!(alias
        .begin_submission(&destination, ConfigCapacityProfile::BoundedV1)
        .is_err());
    drop(restored);
    drop(alias);
    assert!(
        destination.try_reserve().is_err(),
        "TARGET_RETAINED_SUBMISSION_OWNER"
    );
    drop(submission);
    let reservation = destination.try_reserve().unwrap();
    let foreign_caller = AuditCaller::project(&privacy(), "synthetic", "different").unwrap();
    assert!(recover(
        original(&state).as_bytes(),
        reservation,
        &destination,
        identity(),
        &key(),
        foreign_caller
    )
    .is_err());
    let reservation = destination.try_reserve().unwrap();
    assert!(recover(
        original(&state).as_bytes(),
        reservation,
        &source,
        identity(),
        &key(),
        event().caller
    )
    .is_err());
    drop(other);
    all_slots_available(&destination);
    assert!(state
        .recover_target(&key(), &handle, foreign_caller)
        .is_err());
    let wrong_key = AuditKey::new([0x7e; 32]).unwrap();
    assert!(state
        .recover_target(&wrong_key, &handle, event().caller)
        .is_err());
    assert_eq!(state.sequence, 1);
}

#[tokio::test]
async fn retained_target_legacy_bytes_and_omission_remain_exact() {
    let pool = ConfigPreparationPool::bounded_v1();
    let bounded = signed(payload(&pool, b"null").await);
    let mut effect = bounded.command().effect.clone();
    effect.encrypted_payload = Some(TargetPayloadV1::Running {
        commit: Box::new(bounded.bounded_running().unwrap().commit().clone()),
        confirmation_ownership: None,
    });
    let mut legacy = PreparedTargetMutation::new(bounded.handle().clone(), effect, None);
    resign(&mut legacy);
    drop(bounded);
    all_slots_available(&pool);
    legacy.verify_effect(&key()).unwrap();
    let encoded = legacy.encode().unwrap();
    let mut state = ledger();
    state.admit_target(&key(), legacy.command(), 110).unwrap();
    assert_eq!(original(&state).as_bytes(), encoded);
    let decoded = state
        .recover_target(&key(), legacy.handle(), event().caller)
        .unwrap();
    assert_eq!(
        decoded.encode().unwrap(),
        encoded,
        "TARGET_RETAINED_LEGACY_BYTES"
    );
    assert!(decoded.preparation.is_none());
    let serialized = serde_json::to_value(&state).unwrap();
    assert!(
        serialized.get("target_anchor").is_none(),
        "existing omission transcript"
    );
    let mut omitted: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    omitted["effect"]
        .as_object_mut()
        .unwrap()
        .remove("resolution");
    let omitted = serde_json::to_vec(&omitted).unwrap();
    assert_eq!(PreparedTargetMutation::decode(&omitted).unwrap(), legacy);
    replace_original(&mut state, String::from_utf8(omitted).unwrap());
    assert!(state
        .recover_target(&key(), legacy.handle(), event().caller)
        .is_err());
}

thread_local! {
    static LEGACY_DECODES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

pub(in crate::consensus) fn observe_legacy_decode() {
    LEGACY_DECODES.with(|slot| {
        if let Some(count) = slot.get() {
            slot.set(Some(count + 1));
        }
    });
}

struct LegacyDecodeScope;
impl LegacyDecodeScope {
    fn start() -> Self {
        LEGACY_DECODES.with(|slot| assert!(slot.replace(Some(0)).is_none()));
        Self
    }
    fn finish(self) -> usize {
        LEGACY_DECODES.with(|slot| slot.take().unwrap())
    }
}
impl Drop for LegacyDecodeScope {
    fn drop(&mut self) {
        LEGACY_DECODES.with(|slot| slot.set(None));
    }
}

#[tokio::test]
async fn retained_target_bounded_routing_never_enters_legacy_decoder() {
    let pool = ConfigPreparationPool::bounded_v1();
    let prepared = signed(payload(&pool, b"null").await);
    let mut state = admit(&prepared);
    let saved = original(&state).to_owned();
    let scope = LegacyDecodeScope::start();
    let recovered = state
        .recover_target(&key(), prepared.handle(), event().caller)
        .unwrap();
    let valid_entries = scope.finish();
    assert_eq!(recovered, prepared);
    let malformed_source = json!({"running": {
        "version": 0,
        "schema": "x".repeat(4097),
        "ciphertext_digest": vec![0u8; 32]
    }});
    assert!(saved.contains("\"source\":null"));
    let malformed = saved.replacen(
        "\"source\":null",
        &format!(
            "\"source\":{}",
            serde_json::to_string(&malformed_source).unwrap()
        ),
        1,
    );
    // The routing pass skips contents even when malformed source data occurs
    // before the bounded payload. The complete bounded decoder refuses it.
    replace_original(&mut state, malformed);
    let scope = LegacyDecodeScope::start();
    let rejected = state.recover_target(&key(), prepared.handle(), event().caller);
    let invalid_entries = scope.finish();
    assert!(rejected.is_err());
    assert_eq!(
        valid_entries, 0,
        "TARGET_RETAINED_STRICT_ROUTE valid original"
    );
    assert_eq!(
        invalid_entries, 0,
        "TARGET_RETAINED_STRICT_ROUTE malformed source"
    );
    replace_original(&mut state, saved);
    state
        .recover_target(&key(), prepared.handle(), event().caller)
        .unwrap();
}
