//! Causal retained-row/decode controls. In-memory SQL isolates SDK allocation
//! and authentication behavior; this is not native WAL or a 32 MiB envelope.

use super::*;

#[path = "config_capacity_957_ledger_decode/reference.rs"]
mod reference;

use crate::audit_authority::continuity::AuditSigningKey;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditOperationBinding, AuditPrivacyKey, AuditPrivacyProjection, AuditPrivacyPurpose,
    ProjectedAuditEvent,
};
use crate::consensus::config_capacity_simultaneous_working_tests::ledger::{
    self as observation, ObservationGuard, Sample,
};

fn fixture(operations: u64, epochs: u64) -> (AuditKey, AuditKeyRing, StoredLedger) {
    let key = AuditKey::new([0xA1; 32]).expect("synthetic root key");
    let privacy = AuditPrivacyKey::new([0xA2; 32]).expect("synthetic projection key");
    let identity = ConfigConsensusIdentity::new(
        crate::ConfigConsensusClusterId::from_bytes([0xA3; 32]),
        crate::ConfigConsensusConfigurationId::from_bytes([0xA4; 32]),
        crate::ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
    );
    let keys = AuditKeyRing::new(
        (1..=epochs)
            .map(|epoch| {
                AuditSigningKey::new(epoch, [0xB0 + epoch as u8; 32])
                    .expect("distinct synthetic signing key")
            })
            .collect(),
    )
    .expect("bounded signing epochs");
    let mut ledger = LedgerState::new(
        identity,
        privacy
            .project(AuditPrivacyPurpose::KeyIdentity, &[])
            .expect("projection identity"),
        AuditLedgerLimits::new(4096, 1024).expect("unchanged admitted logical limits"),
    );
    ledger.continuity = Some(ContinuityState::new(1));
    for number in 0..operations {
        let mut request = [0xA5; 16];
        request[..8].copy_from_slice(&number.to_be_bytes());
        let record = crate::ManagementAuditEventRecord::try_new(
            request,
            crate::ManagementAuditInstant::try_new(
                100,
                1,
                1,
                crate::ManagementAuditTimeSourceCode::NodeClock,
            )
            .expect("synthetic time"),
            "test",
            "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0",
            crate::ManagementAuditTransportCode::Gnmi,
            crate::ManagementAuditOperationCode::Update,
            crate::ManagementAuditOutcomeCode::Intent,
            None::<&str>,
            ["/fixture:configuration"],
            Some("synthetic-decode-control"),
        )
        .expect("synthetic bounded event");
        let event =
            ProjectedAuditEvent::project(&privacy, &record).expect("actual event projection");
        let binding = AuditOperationBinding::project(&privacy, &event, 0, b"synthetic operation")
            .expect("actual binding");
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity,
                binding,
                event,
                issued_at: 100,
                expires_at: 160,
                nonce: request,
                key_epoch: key.epoch(),
                mutation: None,
            },
            &key,
        )
        .expect("authenticated original handle");
        ledger.admit(&key, &handle, 100).expect("real admission");
        ledger
            .resolve(&key, &handle, AuditOperationState::Rejected)
            .expect("real result");
        ledger
            .acknowledge_terminal(&key, &handle)
            .expect("real terminal acknowledgement");
    }
    ledger
        .seal_continuity(Some(&keys))
        .expect("real signed rows");
    for epoch in 2..=epochs {
        let previous = ledger.continuity.as_ref().expect("continuity").terminal;
        let transition = AuditKeyTransition::prepare(
            &keys,
            identity,
            ledger.sequence,
            previous,
            epoch - 1,
            epoch,
        )
        .expect("real cross-authenticated transition");
        ledger
            .transition_key(&key, &keys, &transition)
            .expect("real epoch transition");
    }
    ledger
        .validate(&key, identity)
        .expect("valid retained ledger");
    ledger
        .validate_continuity(Some(&keys))
        .expect("valid complete signed history");
    (
        key,
        keys,
        StoredLedger {
            identity,
            ledger: Some(ledger),
        },
    )
}

fn database(key: &AuditKey, stored: &StoredLedger) -> Connection {
    let connection = Connection::open_in_memory().expect("unit SQL control");
    connection
        .execute_batch(
            "CREATE TABLE config_raft_management_audit \
             (singleton INTEGER PRIMARY KEY, state_json BLOB, state_hmac BLOB); \
             CREATE TABLE config_raft_identity \
             (singleton INTEGER PRIMARY KEY, cluster_id BLOB, configuration_id BLOB, configuration_epoch INTEGER);",
        )
        .expect("minimal retained-state tables");
    connection
        .execute(
            "INSERT INTO config_raft_identity VALUES (1, ?1, ?2, ?3)",
            params![
                stored.identity.cluster_id().as_bytes().as_slice(),
                stored.identity.configuration_id().as_bytes().as_slice(),
                stored.identity.configuration_epoch().get() as i64,
            ],
        )
        .expect("exact independent SQL identity");
    write_sync(
        &connection,
        key,
        stored.identity,
        stored.ledger.clone(),
        true,
    )
    .expect("actual canonical storage encoder");
    connection
}

fn row(connection: &Connection) -> (Vec<u8>, Vec<u8>, u64) {
    connection
        .query_row(
            "SELECT state_json, state_hmac, total_changes() FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("exact row and write count")
}

fn reject_without_effects(
    connection: &mut Connection,
    key: &AuditKey,
    keys: &AuditKeyRing,
    identity: ConfigConsensusIdentity,
) -> observation::Observation {
    let before = row(connection);
    let transaction = connection.transaction().expect("actual read transaction");
    let observed = ObservationGuard::start(Sample::default());
    let result = read_with_keys_sync(&transaction, key, Some(keys), identity);
    let measured = observed.finish();
    assert!(
        result.is_err(),
        "malformed or over-count retained state must refuse"
    );
    transaction
        .commit()
        .expect("commit unchanged read transaction");
    assert!(
        row(connection) == before,
        "refusal leaves bytes, MAC and write count unchanged"
    );
    measured
}

#[test]
fn config_capacity_957_retained_decode_borrows_sql_row() {
    let (key, keys, stored) = fixture(3, 1);
    let mut connection = database(&key, &stored);
    let before = row(&connection);
    // Calibrate the existing observer against an actual owned SQL result, not
    // a length or scalar charge. This allocation is dropped before the read.
    let control = ObservationGuard::start(Sample::default());
    let owned: Vec<u8> = connection
        .query_row(
            "SELECT state_json FROM config_raft_management_audit",
            [],
            |row| row.get(0),
        )
        .expect("real owned-row control");
    let actual_capacity = owned.capacity();
    drop(observation::EncodedRead::observe(owned));
    let control = control.finish();
    assert_eq!(control.peak.row_json, actual_capacity);
    assert!(actual_capacity > 0);
    // This also checks the zero-charge hook without eliminating its read count.
    let control = ObservationGuard::start(Sample::default());
    drop(observation::borrowed_read(&before.0));
    assert_eq!(control.finish().reads, 1);

    let transaction = connection.transaction().expect("actual read transaction");
    let observed = ObservationGuard::start(Sample::default());
    let read = read_with_keys_sync(&transaction, &key, Some(&keys), stored.identity)
        .expect("full authenticated read");
    let measured = observed.finish();
    assert!(
        read == stored.ledger,
        "the same complete authenticated state returns"
    );
    transaction.commit().expect("read transaction");
    assert!(row(&connection) == before, "read has no effects");
    assert_eq!(measured.reads, 1, "reader was actually observed");
    assert!(
        measured.peak.decoded_ledger > 0,
        "actual decoded owner remains charged"
    );
    assert_eq!(
        measured.peak.row_json, 0,
        "retained read must borrow the SQL blob"
    );
}

#[test]
fn config_capacity_957_retained_decode_exact_collection_reservations() {
    let (key, keys, stored) = fixture(3, 1);
    let mut connection = database(&key, &stored);
    let transaction = connection.transaction().expect("actual read transaction");
    let ledger = read_with_keys_sync(&transaction, &key, Some(&keys), stored.identity)
        .expect("full authentication and continuity")
        .expect("active ledger");
    transaction.commit().expect("unchanged read transaction");
    assert_eq!(ledger.entries.len(), 9);
    assert_eq!(ledger.operations.len(), 3);
    assert_eq!(
        ledger.entries.capacity(),
        ledger.entries.len(),
        "entries reserve their validated count"
    );
    assert_eq!(
        ledger.operations.capacity(),
        ledger.operations.len(),
        "operations reserve their validated count"
    );
    let rows = &ledger.continuity.as_ref().expect("signed rows").rows;
    assert_eq!(
        rows.capacity(),
        rows.len(),
        "continuity rows reserve their validated count"
    );
}

fn assert_overcount_refuses_before_owned_ledger(target: &str) {
    let (key, keys, mut stored) = fixture(3, 1);
    let ledger = stored.ledger.as_mut().expect("active ledger");
    match target {
        "entries" => ledger.entries.resize(4097, ledger.entries[0].clone()),
        "operations" => ledger.operations.resize(1025, ledger.operations[0].clone()),
        "rows" => {
            let rows = &mut ledger.continuity.as_mut().expect("continuity").rows;
            rows.resize(4097, rows[0].clone());
        }
        "declared-limits" => {
            ledger.limits = AuditLedgerLimits::new(3, 1).expect("smaller valid limits")
        }
        _ => unreachable!(),
    }
    // Deliberately authenticated but structurally over-count retained rows.
    // The old parser really constructs these owned collections before the
    // unchanged logical/continuity validators reject them.
    let mut connection = database(&key, &stored);
    assert!(row(&connection).0.len() < MAX_STATE_BYTES);
    for decode in [ledger_decode::decode, reference::decode] {
        let probe = ledger_decode::decode_probe::Guard::start(None);
        assert!(decode(&row(&connection).0).is_err());
        let measured = probe.finish();
        assert_eq!(measured.preflight_passes, 1);
        assert_eq!(measured.owned_passes, 0);
        assert_eq!(measured.reserve_calls, 0);
        assert_eq!(measured.constructed_elements, 0);
    }
    let measured = reject_without_effects(&mut connection, &key, &keys, stored.identity);
    assert_eq!(measured.reads, 1);
    assert_eq!(
        measured.peak.decoded_ledger, 0,
        "over-count {target} must refuse before constructing owned collections"
    );
}

#[test]
fn config_capacity_957_retained_decode_overcount_entries() {
    assert_overcount_refuses_before_owned_ledger("entries");
}

#[test]
fn config_capacity_957_retained_decode_overcount_operations() {
    assert_overcount_refuses_before_owned_ledger("operations");
}

#[test]
fn config_capacity_957_retained_decode_overcount_rows() {
    assert_overcount_refuses_before_owned_ledger("rows");
}

#[test]
fn config_capacity_957_retained_decode_overcount_declared_limits() {
    assert_overcount_refuses_before_owned_ledger("declared-limits");
}

#[test]
fn config_capacity_957_retained_decode_malformed_and_authentication_refuse_without_effects() {
    let (key, keys, stored) = fixture(3, 1);
    let mut connection = database(&key, &stored);
    let (original, mac, _) = row(&connection);
    let text = String::from_utf8(original.clone()).expect("JSON UTF-8");
    let malformed = [
        original[..original.len() - 1].to_vec(),
        text.replacen("\"entries\":", "\"unexpected\":", 1)
            .into_bytes(),
        text.replacen("\"intent\":", "\"unknown-payload\":", 1)
            .into_bytes(),
        text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1)
            .into_bytes(),
    ];
    for encoded in malformed {
        assert!(encoded != original, "control must change real JSON");
        connection
            .execute(
                "UPDATE config_raft_management_audit SET state_json=?1",
                params![encoded],
            )
            .expect("malformed row control");
        reject_without_effects(&mut connection, &key, &keys, stored.identity);
    }
    let mut invalid_mac = mac.clone();
    invalid_mac[0] ^= 1;
    connection
        .execute(
            "UPDATE config_raft_management_audit SET state_json=?1,state_hmac=?2",
            params![&original, invalid_mac],
        )
        .expect("MAC control");
    reject_without_effects(&mut connection, &key, &keys, stored.identity);
    connection
        .execute(
            "UPDATE config_raft_management_audit SET state_hmac=?1",
            params![mac],
        )
        .expect("restore actual authenticator");
    let wrong_key = AuditKey::new([0xA6; 32]).expect("distinct key");
    reject_without_effects(&mut connection, &wrong_key, &keys, stored.identity);
    connection
        .execute("UPDATE config_raft_identity SET configuration_epoch=2", [])
        .expect("independent identity mismatch");
    reject_without_effects(&mut connection, &key, &keys, stored.identity);
    connection
        .execute("UPDATE config_raft_identity SET configuration_epoch=1", [])
        .expect("restore identity");
    assert!(
        read_with_keys_sync(&connection, &key, Some(&keys), stored.identity)
            .expect("original exact restoration")
            == stored.ledger
    );
    for signed_layer in ["ledger-entry", "continuity-row"] {
        let mut ledger = stored.ledger.clone().expect("active fixture");
        if signed_layer == "ledger-entry" {
            ledger.entries[0].mac[0] ^= 1;
        } else {
            ledger.continuity.as_mut().expect("real signed rows").rows[0].signature[0] ^= 1;
        }
        // A valid new outer canonical MAC must not bypass either inner layer.
        write_sync(&connection, &key, stored.identity, Some(ledger), false)
            .expect("re-authenticated malformed inner layer");
        let measured = reject_without_effects(&mut connection, &key, &keys, stored.identity);
        assert!(
            measured.peak.decoded_ledger > 0,
            "valid counts reach the unchanged {signed_layer} verifier"
        );
    }
    write_sync(
        &connection,
        &key,
        stored.identity,
        stored.ledger.clone(),
        false,
    )
    .expect("restore exact fixture");
    let before = row(&connection);
    assert!(
        read_with_keys_sync(&connection, &key, None, stored.identity).is_err(),
        "signed continuity still needs its independent keys"
    );
    let other_identity = ConfigConsensusIdentity::new(
        stored.identity.cluster_id(),
        stored.identity.configuration_id(),
        crate::ConfigConsensusConfigurationEpoch::new(2).expect("different epoch"),
    );
    assert!(
        read_with_keys_sync(&connection, &key, Some(&keys), other_identity).is_err(),
        "the caller's expected identity remains mandatory"
    );
    assert!(
        row(&connection) == before,
        "key/expected-identity refusal has no effects"
    );
}

fn sequence_struct(value: &mut serde_json::Value, fields: &[&str]) {
    let object = value.as_object_mut().expect("derived map representation");
    let values = fields
        .iter()
        .map(|field| object.remove(*field).expect("real field"))
        .collect();
    assert!(object.is_empty(), "test representation covers every field");
    *value = serde_json::Value::Array(values);
}

#[test]
fn config_capacity_957_retained_decode_preserves_accepted_json_forms() {
    let (key, keys, stored) = fixture(3, 1);
    let mut connection = database(&key, &stored);
    let (original, _, _) = row(&connection);
    let escaped = format!(
        " \n{}\t ",
        String::from_utf8(original.clone())
            .expect("JSON")
            .replace("\"entries\"", "\"entr\\u0069es\"")
    );
    let mut sequence: serde_json::Value =
        serde_json::from_slice(&original).expect("synthetic test representation");
    sequence_struct(
        &mut sequence["ledger"]["continuity"],
        &[
            "version",
            "initial_epoch",
            "floor_epoch",
            "floor_anchor",
            "active_epoch",
            "terminal",
            "rows",
            "checkpoint",
            "export_checkpoint",
        ],
    );
    sequence_struct(
        &mut sequence["ledger"],
        &[
            "version",
            "identity",
            "projection",
            "limits",
            "sequence",
            "terminal",
            "floor",
            "predecessor",
            "entries",
            "operations",
            "continuity",
        ],
    );
    sequence_struct(&mut sequence, &["identity", "ledger"]);
    let mut extended: serde_json::Value =
        serde_json::from_slice(&original).expect("synthetic test representation");
    extended["ledger"]["entries"][1]["payload"]["outcome"]["ignored"] =
        serde_json::Value::String("x".repeat(65_536));
    let chain = extended["ledger"]["continuity"]
        .as_object_mut()
        .expect("continuity map");
    chain.remove("checkpoint");
    chain.remove("export_checkpoint");
    for encoded in [
        escaped.into_bytes(),
        serde_json::to_vec(&sequence).expect("sequence representation"),
        serde_json::to_vec(&extended).expect("ignored extension"),
    ] {
        assert_decoder_parity(&encoded);
        let previous: StoredLedger =
            serde_json::from_slice(&encoded).expect("previous derived decoder accepts this form");
        assert!(previous.ledger == stored.ledger && previous.identity == stored.identity);
        connection
            .execute(
                "UPDATE config_raft_management_audit SET state_json=?1",
                params![encoded],
            )
            .expect("noncanonical compatible form");
        let before = row(&connection);
        let transaction = connection.transaction().expect("actual read transaction");
        assert!(
            read_with_keys_sync(&transaction, &key, Some(&keys), stored.identity)
                .expect("original canonical MAC still authenticates")
                == stored.ledger
        );
        transaction.commit().expect("read transaction");
        assert!(
            row(&connection) == before,
            "compatible read does not canonicalize storage"
        );
    }
}

fn assert_decoder_parity(encoded: &[u8]) -> StoredLedger {
    let old = reference::decode(encoded).expect("previous bounded decoder accepts form");
    let current = ledger_decode::decode(encoded).expect("single owned pass accepts form");
    assert!(old.identity == current.identity && old.ledger == current.ledger);
    assert_eq!(
        serde_json::to_vec(&old).expect("old canonical form"),
        serde_json::to_vec(&current).expect("current canonical form"),
        "exact canonical bytes, including every original signed entry and handle"
    );
    current
}

#[test]
fn config_capacity_957_retained_decode_single_pass_parity() {
    for operations in [0, 1, 3, 1024] {
        let (_, _, mut stored) = fixture(operations, if operations == 1024 { 8 } else { 1 });
        for continuity in [true, false] {
            if !continuity {
                stored.ledger.as_mut().expect("active ledger").continuity = None;
            }
            let encoded = serde_json::to_vec(&stored).expect("real bounded history");
            let current = assert_decoder_parity(&encoded);
            assert!(current.identity == stored.identity && current.ledger == stored.ledger);
            let pretty = serde_json::to_vec_pretty(&stored).expect("accepted whitespace");
            assert_decoder_parity(&pretty);
            // serde_json::Value sorts map keys, putting continuity before the
            // other arrays. The owned seed must not depend on canonical order.
            let reordered: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            assert_decoder_parity(&serde_json::to_vec(&reordered).unwrap());
        }
        stored.ledger = None;
        assert_decoder_parity(&serde_json::to_vec(&stored).unwrap());
    }
}

#[test]
fn config_capacity_957_retained_decode_single_pass_collection_boundaries() {
    let (_, _, source) = fixture(3, 1);
    for (events, operations) in [(0, 0), (1, 1), (4096, 1024)] {
        let mut stored = StoredLedger {
            identity: source.identity,
            ledger: source.ledger.clone(),
        };
        let ledger = stored.ledger.as_mut().unwrap();
        // These are structural decoder boundaries, not invented valid ledger
        // histories. Independent logical/authentication validation is unchanged.
        ledger.entries.resize(events, ledger.entries[0].clone());
        ledger
            .operations
            .resize(operations, ledger.operations[0].clone());
        let rows = &mut ledger.continuity.as_mut().unwrap().rows;
        rows.resize(events, rows[0].clone());
        let current = assert_decoder_parity(&serde_json::to_vec(&stored).unwrap());
        let ledger = current.ledger.unwrap();
        assert_eq!(ledger.entries.capacity(), events);
        assert_eq!(ledger.operations.capacity(), operations);
        assert_eq!(ledger.continuity.unwrap().rows.capacity(), events);
    }
}

#[test]
fn config_capacity_957_retained_decode_single_pass_traversal() {
    let (_, _, mut stored) = fixture(3, 2);
    for continuity in [true, false] {
        if !continuity {
            stored.ledger.as_mut().expect("active ledger").continuity = None;
        }
        let encoded = serde_json::to_vec(&stored).unwrap();
        let ledger = stored.ledger.as_ref().unwrap();
        let elements = ledger.entries.len()
            + ledger.operations.len()
            + ledger
                .continuity
                .as_ref()
                .map_or(0, |chain| chain.rows.len());
        let probe = ledger_decode::decode_probe::Guard::start(None);
        let current = ledger_decode::decode(&encoded).expect("real production decoder");
        let measured = probe.finish();
        assert!(current.ledger == stored.ledger);
        assert_eq!(measured.preflight_passes, 1);
        assert_eq!(
            measured.owned_passes, 1,
            "LEDGER_SINGLE_OWNED_PASS: construct every owned collection in one traversal"
        );
        assert_eq!(measured.traversed_input_bytes, encoded.len() * 2);
        assert_eq!(measured.reserve_calls, if continuity { 3 } else { 2 });
        assert_eq!(measured.requested_elements, elements);
        assert_eq!(measured.constructed_elements, elements);
        assert!(!measured.allocation_fault_injected);
        let probe = ledger_decode::decode_probe::Guard::start(None);
        let old = reference::decode(&encoded).expect("real previous decoder control");
        let control = probe.finish();
        assert!(old.ledger == current.ledger);
        assert_eq!(control.preflight_passes, 1);
        assert_eq!(control.owned_passes, if continuity { 3 } else { 2 });
        assert_eq!(control.reserve_calls, measured.reserve_calls);
        assert_eq!(control.requested_elements, measured.requested_elements);
        assert_eq!(control.constructed_elements, measured.constructed_elements);
        assert_eq!(
            control.traversed_input_bytes,
            encoded.len() * (control.owned_passes + 1)
        );
        println!("CONFIG_CAPACITY_LEDGER_SINGLE_PASS continuity={continuity} bytes={} current_passes={} reference_passes={} requested_elements={elements} constructed_elements={} parity=true", encoded.len(), measured.preflight_passes + measured.owned_passes, control.preflight_passes + control.owned_passes, measured.constructed_elements);
    }
}

#[test]
fn config_capacity_957_retained_decode_single_pass_adversarial_parity() {
    let (_, _, stored) = fixture(3, 1);
    let encoded = serde_json::to_vec(&stored).unwrap();
    let text = String::from_utf8(encoded.clone()).unwrap();
    let mut malformed = vec![
        format!("{text} null").into_bytes(),
        text.replacen("\"ledger\":", "\"ledger\":null,\"ledger\":", 1)
            .into_bytes(),
        text.replacen("\"entries\":", "\"entries\":[],\"entries\":", 1)
            .into_bytes(),
        text.replacen("\"rows\":", "\"rows\":[],\"rows\":", 1)
            .into_bytes(),
        text.replacen("\"version\":1", "\"version\":65536", 1)
            .into_bytes(),
        text.replacen("\"intent\":", "\"unknown-payload\":", 1)
            .into_bytes(),
        text.replacen("\"operations\":", "\"unexpected\":", 1)
            .into_bytes(),
    ];
    for end in [0, 1, encoded.len() / 2, encoded.len() - 1] {
        malformed.push(encoded[..end].to_vec());
    }
    for field in ["entries", "operations"] {
        for value in [
            serde_json::Value::Null,
            serde_json::json!({}),
            serde_json::json!([null]),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
            changed["ledger"][field] = value;
            malformed.push(serde_json::to_vec(&changed).unwrap());
        }
    }
    for bytes in malformed {
        assert_ne!(bytes, encoded, "malformed control must alter the real row");
        let old = reference::decode(&bytes)
            .err()
            .expect("previous decoder must reject");
        let current = ledger_decode::decode(&bytes)
            .err()
            .expect("current decoder must reject");
        assert_eq!(old.kind(), current.kind());
    }
}

#[test]
fn config_capacity_957_retained_decode_single_pass_allocation_failure() {
    let (key, keys, stored) = fixture(3, 1);
    let mut connection = database(&key, &stored);
    for fail_after in 0..3 {
        let before = row(&connection);
        let probe = ledger_decode::decode_probe::Guard::start(Some(fail_after));
        reject_without_effects(&mut connection, &key, &keys, stored.identity);
        let measured = probe.finish();
        assert!(
            measured.allocation_fault_injected,
            "actual try_reserve_exact refusal"
        );
        assert_eq!(measured.reserve_calls, fail_after + 1);
        assert_eq!(measured.constructed_elements, [0, 9, 12][fail_after]);
        assert!(row(&connection) == before);
        assert!(
            read_with_keys_sync(&connection, &key, Some(&keys), stored.identity)
                .expect("original signed row still authenticates")
                == stored.ledger
        );
    }
}

#[test]
fn config_capacity_957_retained_decode_reachable_limit_roundtrip() {
    let (key, keys, stored) = fixture(1024, 8);
    let mut connection = database(&key, &stored);
    let before = row(&connection);
    let transaction = connection.transaction().expect("actual read transaction");
    let ledger = read_with_keys_sync(&transaction, &key, Some(&keys), stored.identity)
        .expect("authenticate maximum operation/epoch fixture")
        .expect("active ledger");
    assert_eq!(
        ledger.entries.len(),
        3079,
        "3072 real lifecycle rows and seven transitions"
    );
    assert_eq!(ledger.operations.len(), 1024);
    assert_eq!(
        ledger
            .continuity
            .as_ref()
            .expect("real signed rows")
            .rows
            .len(),
        3079
    );
    println!(
        "CONFIG_CAPACITY_RETAINED_DECODE_COLLECTIONS entries_capacity={} operations_capacity={} rows_capacity={} owned_payload_bytes={}",
        ledger.entries.capacity(), ledger.operations.capacity(),
        ledger.continuity.as_ref().expect("signed rows").rows.capacity(),
        observation::ledger_heap(&ledger),
    );
    assert!(
        Some(ledger) == stored.ledger,
        "all original bytes/handles and logical state survive"
    );
    transaction.commit().expect("read transaction");
    assert!(row(&connection) == before, "at-limit read has no effects");
}

// Growth checks use the actual SQL authority dispatcher and decoded mutable
// owner. These are component controls; the public native detector separately
// retains mandatory completion, exact readback and retained reopen.
fn measured_decoded_growth(continuity: bool) -> observation::Observation {
    let (key, keys, mut stored) = fixture(3, 1);
    if !continuity {
        stored.ledger.as_mut().expect("active ledger").continuity = None;
    }
    let (_, _, fourth) = fixture(4, 1);
    let handle = fourth.ledger.expect("real fourth lifecycle").operations[3]
        .handle
        .clone();
    let signing = continuity.then_some(&keys);
    let mut connection = database(&key, &stored);
    let before = row(&connection);
    let transaction = connection.transaction().expect("real apply transaction");
    let observed = ObservationGuard::start(Sample::default());
    apply_sync(
        &transaction,
        &key,
        stored.identity,
        &AuditCommand::Intent(handle.clone()),
        100,
        signing,
    )
    .expect("actual authority dispatcher")
    .expect("new original Intent admitted");
    let measured = observed.finish();
    transaction.commit().expect("commit actual Intent");
    let admitted = read_with_keys_sync(&connection, &key, signing, stored.identity)
        .expect("complete authenticated readback")
        .expect("active ledger");
    let receipt = admitted
        .lookup(&key, &handle, handle.body.binding.caller)
        .expect("original authenticated lookup")
        .expect("actual new operation");
    assert_eq!(receipt.state(), AuditOperationState::Intent);
    let mut expected = stored.ledger.expect("original prefix");
    expected
        .admit(&key, &handle, 100)
        .expect("real expected transition");
    expected
        .seal_continuity(signing)
        .expect("real expected signatures");
    assert!(
        admitted == expected,
        "exact canonical state and original handles"
    );
    let after = row(&connection);
    assert_eq!(after.2, before.2 + 1, "one authoritative row write");
    assert!(after.0 != before.0 && after.1 != before.1);
    // Complete the genuine retained operation before checking allocation shape.
    for command in [
        AuditCommand::Reject(handle.clone()),
        AuditCommand::Terminal(handle.clone()),
    ] {
        let transaction = connection.transaction().expect("completion transaction");
        apply_sync(&transaction, &key, stored.identity, &command, 100, signing)
            .expect("real completion apply")
            .expect("reserved completion admitted");
        transaction.commit().expect("commit actual completion");
    }
    let completed = read_with_keys_sync(&connection, &key, signing, stored.identity)
        .expect("authenticated complete retained read")
        .expect("active ledger");
    let recovered = completed
        .lookup(&key, &handle, handle.body.binding.caller)
        .expect("authenticate original handle")
        .expect("original retained operation");
    assert_eq!(recovered.state(), AuditOperationState::Rejected);
    assert!(recovered.terminal_recorded());
    assert_eq!(
        measured.mutation_owners, 1,
        "one actual decoded apply owner"
    );
    let initial = measured.mutation_initial.expect("decoded retained owner");
    let final_collections = measured.mutation_final.expect("mutated retained owner");
    assert_eq!(initial.lengths, [9, 3, if continuity { 9 } else { 0 }]);
    assert_eq!(
        initial.capacities, initial.lengths,
        "real exact decoder input"
    );
    assert_eq!(
        final_collections.lengths,
        [10, 4, if continuity { 10 } else { 0 }]
    );
    println!(
        "CONFIG_CAPACITY_LEDGER_GROWTH_SQL continuity={continuity} initial={initial:?} final={final_collections:?} original_recovery=true terminal=true"
    );
    measured
}

#[test]
fn config_capacity_957_ledger_growth_entries() {
    for continuity in [false, true] {
        let measured = measured_decoded_growth(continuity);
        let final_collections = measured.mutation_final.expect("actual owner");
        assert_eq!(
            final_collections.capacities[0], final_collections.lengths[0],
            "LEDGER_GROWTH_ENTRIES: decoded append must reserve only the new entry"
        );
    }
}

#[test]
fn config_capacity_957_ledger_growth_operations() {
    for continuity in [false, true] {
        let measured = measured_decoded_growth(continuity);
        let final_collections = measured.mutation_final.expect("actual owner");
        assert_eq!(
            final_collections.capacities[1], final_collections.lengths[1],
            "LEDGER_GROWTH_OPERATIONS: admission must reserve only the new operation"
        );
    }
}

#[test]
fn config_capacity_957_ledger_growth_rows() {
    let measured = measured_decoded_growth(true);
    let final_collections = measured.mutation_final.expect("actual owner");
    assert_eq!(
        final_collections.capacities[2], final_collections.lengths[2],
        "LEDGER_GROWTH_ROWS: sealing must reserve only the new signed row"
    );
}

#[test]
fn config_capacity_957_ledger_growth_full_and_exact_retry_preserve_bytes() {
    let (key, keys, mut stored) = fixture(3, 1);
    let ledger = stored.ledger.as_mut().expect("active ledger");
    ledger.limits = AuditLedgerLimits::new(9, 3).expect("original supported limits");
    let existing = ledger.operations[0].handle.clone();
    let (_, _, fourth) = fixture(4, 1);
    let handle = fourth.ledger.expect("real fourth lifecycle").operations[3]
        .handle
        .clone();
    let mut connection = database(&key, &stored);
    let before = row(&connection);
    let transaction = connection.transaction().expect("full apply transaction");
    assert!(matches!(
        apply_sync(
            &transaction,
            &key,
            stored.identity,
            &AuditCommand::Intent(handle),
            100,
            Some(&keys),
        ),
        Ok(Err(ConfigMutationFailure::HistoryFull))
    ));
    transaction
        .commit()
        .expect("unchanged rejection transaction");
    assert!(
        row(&connection) == before,
        "logical capacity refusal has no effects"
    );
    let transaction = connection.transaction().expect("exact retry transaction");
    apply_sync(
        &transaction,
        &key,
        stored.identity,
        &AuditCommand::Intent(existing.clone()),
        100,
        Some(&keys),
    )
    .expect("retry apply")
    .expect("exact admitted retry remains valid at the limit");
    transaction.commit().expect("retry transaction");
    let after = row(&connection);
    assert!(after.0 == before.0 && after.1 == before.1);
    let read = read_with_keys_sync(&connection, &key, Some(&keys), stored.identity)
        .expect("full authentication and continuity")
        .expect("active ledger");
    assert!(Some(read.clone()) == stored.ledger);
    let receipt = read
        .lookup(&key, &existing, existing.body.binding.caller)
        .expect("authenticate original operation")
        .expect("retained original result");
    assert_eq!(receipt.state(), AuditOperationState::Rejected);
    assert!(receipt.terminal_recorded());
}

#[test]
fn config_capacity_957_ledger_growth_intent_allocation_failure_is_storage_error() {
    use crate::audit_authority::ledger::allocation_probe::FailureGuard;

    for fail_after in 0..3 {
        let (key, keys, stored) = fixture(3, 1);
        let (_, _, fourth) = fixture(4, 1);
        let handle = fourth.ledger.expect("real fourth lifecycle").operations[3]
            .handle
            .clone();
        let mut connection = database(&key, &stored);
        let before = row(&connection);
        let transaction = connection.transaction().expect("actual apply transaction");
        let fault = FailureGuard::start(fail_after);
        let result = apply_sync(
            &transaction,
            &key,
            stored.identity,
            &AuditCommand::Intent(handle),
            100,
            Some(&keys),
        );
        assert!(
            result.is_err(),
            "LEDGER_GROWTH_ALLOCATION_IS_STORAGE: local allocation refusal cannot be a replicated command result"
        );
        assert!(
            fault.injected(),
            "actual reservation produced TryReserveError"
        );
        drop(fault);
        transaction
            .commit()
            .expect("no authoritative mutation to commit");
        assert!(
            row(&connection) == before,
            "no result or ledger write on allocation failure"
        );
        assert!(
            read_with_keys_sync(&connection, &key, Some(&keys), stored.identity)
                .expect("original state still authenticates")
                == stored.ledger
        );
    }
}

#[test]
fn config_capacity_957_ledger_growth_transition_allocation_failure_is_storage_error() {
    use crate::audit_authority::ledger::allocation_probe::FailureGuard;

    let (key, _, stored) = fixture(3, 1);
    let (_, keys, _) = fixture(3, 2);
    let ledger = stored.ledger.as_ref().expect("original signing prefix");
    let chain = ledger.continuity.as_ref().expect("original continuity");
    let transition = AuditKeyTransition::prepare(
        &keys,
        stored.identity,
        ledger.sequence,
        chain.terminal,
        1,
        2,
    )
    .expect("actual accepted next transition");
    let mut connection = database(&key, &stored);
    let before = row(&connection);
    let transaction = connection
        .transaction()
        .expect("actual transition transaction");
    // Append succeeds; the real following signing-row reservation refuses.
    let fault = FailureGuard::start(1);
    let result = apply_sync(
        &transaction,
        &key,
        stored.identity,
        &AuditCommand::Transition(transition),
        100,
        Some(&keys),
    );
    assert!(
        result.is_err(),
        "LEDGER_GROWTH_TRANSITION_STORAGE: post-append allocation refusal cannot become HistoryFull"
    );
    assert!(
        fault.injected(),
        "actual signing reservation produced TryReserveError"
    );
    drop(fault);
    transaction
        .commit()
        .expect("no authoritative transition to commit");
    assert!(
        row(&connection) == before,
        "original epoch and exact bytes remain"
    );
    assert!(
        read_with_keys_sync(&connection, &key, Some(&keys), stored.identity)
            .expect("original signing prefix still authenticates")
            == stored.ledger
    );
}
