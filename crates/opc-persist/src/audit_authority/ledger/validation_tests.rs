use std::io::Write;
use std::mem::size_of;
use std::time::Instant;

use super::*;
use crate::audit_authority::continuity::chain::{ContinuityState, SignedAuditRow};
use crate::audit_authority::AuditPrivacyKey;
use crate::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
};

mod reference;

type MutationCase = (&'static str, fn(&mut LedgerState));

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::from_bytes([0xA1; 32]),
        ConfigConsensusConfigurationId::from_bytes([0xA2; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn key() -> AuditKey {
    AuditKey::new([0xA3; 32]).unwrap()
}

fn handle(number: u64, outcome: ManagementAuditOutcomeCode) -> AuditOperationHandle {
    let privacy = AuditPrivacyKey::new([0xA4; 32]).unwrap();
    let mut request = [0xA5; 16];
    request[..8].copy_from_slice(&number.to_be_bytes());
    let event = ManagementAuditEventRecord::try_new(
        request,
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        "synthetic",
        "spiffe://qualification.invalid/ledger-index",
        ManagementAuditTransportCode::Gnmi,
        ManagementAuditOperationCode::Update,
        outcome,
        None::<&str>,
        ["/fixture:configuration"],
        Some("synthetic-validation-index"),
    )
    .unwrap();
    let event = ProjectedAuditEvent::project(&privacy, &event).unwrap();
    let binding =
        AuditOperationBinding::project(&privacy, &event, 0, b"synthetic operation").unwrap();
    AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding,
            event,
            issued_at: 100,
            expires_at: 160,
            nonce: request,
            key_epoch: key().epoch(),
            mutation: None,
        },
        &key(),
    )
    .unwrap()
}

fn empty() -> LedgerState {
    LedgerState::new(
        identity(),
        handle(0, ManagementAuditOutcomeCode::Intent)
            .body
            .event
            .projection,
        AuditLedgerLimits::new(4096, 1024).unwrap(),
    )
}

fn completed(count: usize) -> LedgerState {
    let mut ledger = empty();
    for number in 0..count {
        let operation = handle(number as u64, ManagementAuditOutcomeCode::Intent);
        ledger.admit(&key(), &operation, 110).unwrap();
        ledger
            .resolve(&key(), &operation, AuditOperationState::Rejected)
            .unwrap();
        ledger.acknowledge_terminal(&key(), &operation).unwrap();
    }
    ledger
}

fn equivalent(ledger: &LedgerState, expected: Result<(), AuditAuthorityError>, label: &str) {
    let before = ledger.clone();
    assert_eq!(
        reference::validate(ledger, &key(), identity()),
        expected,
        "reference: {label}"
    );
    assert_eq!(
        ledger.validate(&key(), identity()),
        expected,
        "indexed: {label}"
    );
    assert!(*ledger == before, "validation cannot mutate state: {label}");
}

// Reauthenticate deliberately malformed histories so their semantic rejection
// cannot be explained by a stale chain MAC alone.
fn resign(ledger: &mut LedgerState) {
    let mut sequence = ledger.floor;
    let mut previous = ledger.predecessor;
    for entry in &mut ledger.entries {
        sequence = sequence.checked_add(1).unwrap();
        entry.sequence = sequence;
        entry.previous = previous;
        entry.key_epoch = key().epoch();
        entry.mac = authenticate(
            &key(),
            ENTRY_DOMAIN,
            &(
                ledger.identity,
                sequence,
                previous,
                entry.key_epoch,
                &entry.payload,
            ),
        )
        .unwrap();
        previous = entry.mac;
    }
    ledger.sequence = sequence;
    ledger.terminal = previous;
}

#[test]
fn indexed_validation_matches_original_valid_prefixes_and_interleavings() {
    let mut ledger = empty();
    equivalent(&ledger, Ok(()), "empty");
    ledger.floor = 37;
    ledger.sequence = 37;
    ledger.predecessor = [0xA6; 32];
    ledger.terminal = ledger.predecessor;
    equivalent(&ledger, Ok(()), "nonzero retained floor");
    let operations: Vec<_> = (0..8)
        .map(|n| handle(n, ManagementAuditOutcomeCode::Intent))
        .collect();
    for operation in &operations {
        ledger.admit(&key(), operation, 110).unwrap();
        equivalent(&ledger, Ok(()), "admitted prefix");
    }
    ledger
        .append_event(&key(), operations[0].body.event.clone())
        .unwrap();
    equivalent(&ledger, Ok(()), "interleaved event");
    for (position, operation) in operations.iter().enumerate().rev() {
        let outcome = if position % 2 == 0 {
            AuditOperationState::Rejected
        } else {
            AuditOperationState::Committed {
                version: position as u64 + 1,
            }
        };
        ledger.resolve(&key(), operation, outcome).unwrap();
        equivalent(&ledger, Ok(()), "reverse resolution");
    }
    for operation in &operations {
        ledger.acknowledge_terminal(&key(), operation).unwrap();
        equivalent(&ledger, Ok(()), "terminal prefix");
    }
    let observed = handle(99, ManagementAuditOutcomeCode::Success);
    ledger.admit(&key(), &observed, 110).unwrap();
    equivalent(&ledger, Ok(()), "standalone observation");
}

#[test]
fn indexed_validation_matches_original_signed_adversarial_histories() {
    let original = completed(2);
    let mismatch = Err(AuditAuthorityError::BindingMismatch);
    let mutations: &[MutationCase] = &[
        ("duplicate original Intent", |l| {
            l.entries.push(l.entries[0].clone());
        }),
        ("duplicate request with new nonce", |l| {
            let mut body = l.operations[0].handle.body.clone();
            body.nonce[0] ^= 1;
            let duplicate = AuditOperationHandle::issue(body, &key()).unwrap();
            l.entries.push(LedgerEntry {
                payload: EntryPayload::Intent(Box::new(duplicate)),
                ..l.entries[0].clone()
            });
        }),
        ("Outcome before Intent", |l| {
            l.entries.swap(0, 1);
        }),
        ("Terminal before Intent", |l| {
            l.entries.swap(0, 2);
        }),
        ("Outcome references future Intent", |l| {
            l.entries[1].payload = EntryPayload::Outcome {
                operation: l.operations[1].handle.mac,
                state: AuditOperationState::Rejected,
            };
        }),
        ("Terminal references future Intent", |l| {
            l.entries[2].payload = EntryPayload::Terminal {
                operation: l.operations[1].handle.mac,
            };
        }),
        ("unknown Outcome MAC", |l| {
            l.entries[1].payload = EntryPayload::Outcome {
                operation: [0; 32],
                state: AuditOperationState::Rejected,
            };
        }),
        ("unknown Terminal MAC", |l| {
            l.entries[2].payload = EntryPayload::Terminal { operation: [0; 32] };
        }),
        ("Terminal before Outcome", |l| {
            l.entries.swap(1, 2);
        }),
        ("duplicate Outcome", |l| {
            l.entries.insert(2, l.entries[1].clone());
        }),
        ("duplicate Terminal", |l| {
            l.entries.insert(3, l.entries[2].clone());
        }),
        ("Outcome cannot remain Intent", |l| {
            l.entries[1].payload = EntryPayload::Outcome {
                operation: l.operations[0].handle.mac,
                state: AuditOperationState::Intent,
            };
        }),
        ("Outcome cannot become observation", |l| {
            l.entries[1].payload = EntryPayload::Outcome {
                operation: l.operations[0].handle.mac,
                state: AuditOperationState::Observed {
                    outcome: ManagementAuditOutcomeCode::Success,
                },
            };
        }),
        ("wrong signed projection", |l| {
            let mut body = l.operations[0].handle.body.clone();
            body.event.projection = AuditToken::from_keyed_projection([0xFF; 32]).unwrap();
            l.entries[0].payload =
                EntryPayload::Intent(Box::new(AuditOperationHandle::issue(body, &key()).unwrap()));
        }),
        ("stored operations reordered", |l| {
            l.operations.swap(0, 1);
        }),
        ("stored operation omitted", |l| {
            l.operations.pop();
        }),
        ("stored duplicate request", |l| {
            l.operations[1] = l.operations[0].clone();
        }),
        ("wrong reservation", |l| {
            l.operations[0].reserved = 1;
        }),
        ("wrong terminal flag", |l| {
            l.operations[0].terminal_recorded = false;
        }),
        ("first sequence at floor", |l| {
            l.operations[0].first_sequence = l.floor;
        }),
        ("last sequence beyond tail", |l| {
            l.operations[0].last_sequence = 100;
        }),
        ("last before first", |l| {
            l.operations[0].last_sequence = 0;
        }),
    ];
    for (label, mutate) in mutations {
        let mut candidate = original.clone();
        mutate(&mut candidate);
        resign(&mut candidate);
        equivalent(&candidate, mismatch, label);
    }
    let mut observed = empty();
    let operation = handle(2, ManagementAuditOutcomeCode::Success);
    observed.admit(&key(), &operation, 110).unwrap();
    observed
        .append(
            &key(),
            EntryPayload::Outcome {
                operation: operation.mac,
                state: AuditOperationState::Rejected,
            },
        )
        .unwrap();
    equivalent(&observed, mismatch, "Outcome after observation");
}

#[test]
fn indexed_validation_matches_original_authentication_limits_and_overflow() {
    let original = completed(2);
    let mutations: &[MutationCase] = &[
        ("entry MAC", |l| {
            l.entries[0].mac[0] ^= 1;
        }),
        ("entry epoch", |l| {
            l.entries[0].key_epoch += 1;
        }),
        ("entry sequence", |l| {
            l.entries[0].sequence += 1;
        }),
        ("predecessor", |l| {
            l.entries[0].previous[0] ^= 1;
        }),
        ("tail MAC", |l| {
            l.terminal[0] ^= 1;
        }),
        ("tail sequence", |l| {
            l.sequence += 1;
        }),
        ("version", |l| {
            l.version += 1;
        }),
        ("truncated row", |l| {
            l.entries.pop();
        }),
        ("capacity", |l| {
            l.limits = AuditLedgerLimits::new(3, 1).unwrap();
        }),
        ("sequence overflow", |l| {
            l.floor = u64::MAX;
        }),
        ("authenticated wrong handle MAC", |l| {
            if let EntryPayload::Intent(handle) = &mut l.entries[0].payload {
                handle.mac[0] ^= 1;
            }
            resign(l);
        }),
        ("authenticated wrong handle identity", |l| {
            if let EntryPayload::Intent(handle) = &mut l.entries[0].payload {
                handle.body.identity = ConfigConsensusIdentity::new(
                    ConfigConsensusClusterId::from_bytes([0xB0; 32]),
                    identity().configuration_id(),
                    identity().configuration_epoch(),
                );
                handle.mac = authenticate(&key(), HANDLE_DOMAIN, &handle.body).unwrap();
            }
            resign(l);
        }),
    ];
    for (label, mutate) in mutations {
        let mut candidate = original.clone();
        mutate(&mut candidate);
        equivalent(&candidate, Err(AuditAuthorityError::BindingMismatch), label);
    }
    let mut invalid = original.clone();
    invalid.limits.max_events = 0;
    equivalent(
        &invalid,
        Err(AuditAuthorityError::InvalidInput),
        "invalid limit",
    );
    invalid = original;
    invalid.operations[0].reserved = usize::MAX;
    equivalent(
        &invalid,
        Err(AuditAuthorityError::Full),
        "reservation arithmetic overflow",
    );
}

#[test]
fn validation_index_compares_full_keys_and_preserves_first_mac_match() {
    let mut first = handle(1, ManagementAuditOutcomeCode::Intent);
    let mut second = handle(2, ManagementAuditOutcomeCode::Intent);
    let mut request = [0xB1; 32];
    first.body.binding.request = AuditToken::from_keyed_projection(request).unwrap();
    first.body.event.request = first.body.binding.request;
    request[31] ^= 1;
    second.body.binding.request = AuditToken::from_keyed_projection(request).unwrap();
    second.body.event.request = second.body.binding.request;
    first = AuditOperationHandle::issue(first.body, &key()).unwrap();
    second = AuditOperationHandle::issue(second.body, &key()).unwrap();
    let mut ledger = empty();
    ledger.admit(&key(), &first, 110).unwrap();
    ledger.admit(&key(), &second, 110).unwrap();
    equivalent(&ledger, Ok(()), "request difference only in last byte");
    if let EntryPayload::Intent(handle) = &mut ledger.entries[1].payload {
        handle.mac = first.mac;
    }
    ledger.operations[1].handle.mac = first.mac;
    resign(&mut ledger);
    let index = validation_index::ValidationIndex::new(&ledger.entries).unwrap();
    assert!(!index.duplicate_request(0).unwrap());
    assert!(!index.duplicate_request(1).unwrap());
    assert_eq!(index.prior_operation(&first.mac, 0), None);
    assert_eq!(index.prior_operation(&first.mac, 1), Some(0));
    assert_eq!(index.prior_operation(&first.mac, 2), Some(0));
    equivalent(
        &ledger,
        Err(AuditAuthorityError::BindingMismatch),
        "forged duplicate MAC is still authenticated",
    );
    drop(index);
    let mut mac = [0xB2; 32];
    if let EntryPayload::Intent(handle) = &mut ledger.entries[0].payload {
        handle.mac = mac;
    }
    mac[31] ^= 1;
    if let EntryPayload::Intent(handle) = &mut ledger.entries[1].payload {
        handle.mac = mac;
    }
    let index = validation_index::ValidationIndex::new(&ledger.entries).unwrap();
    assert_eq!(index.prior_operation(&mac, 1), None);
    assert_eq!(index.prior_operation(&mac, 2), Some(1));
}

#[test]
fn retained_validation_comparison_work_is_bounded() {
    let ledger = completed(1024);
    assert_eq!(ledger.entries.len(), 3072);
    assert_eq!(ledger.operations.len(), 1024);
    let started = Instant::now();
    let probe = validation_probe::Probe::start(None);
    ledger.validate(&key(), identity()).unwrap();
    let indexed = probe.counts();
    let indexed_elapsed = started.elapsed();
    drop(probe);
    let started = Instant::now();
    let probe = validation_probe::Probe::start(None);
    reference::validate(&ledger, &key(), identity()).unwrap();
    let original = probe.counts();
    let original_elapsed = started.elapsed();
    drop(probe);
    assert_eq!(
        original.comparisons,
        2 * 1024 * 1024,
        "original four scans remain the control"
    );
    assert!(
        indexed.comparisons > 0,
        "production comparisons must be observed"
    );
    assert!(indexed.comparisons <= 128 * 1024, "LEDGER_VALIDATION_INDEX_WORK: sorting and lookup must not scan every prior operation: {indexed:?}");
    assert_eq!(indexed.reserves, 1);
    assert_eq!(indexed.intents, 1024);
    assert_eq!(indexed.capacity, 1024);
    assert_eq!(indexed.bitmap_bytes, 512);
    assert_eq!(indexed.peak_indexes, 1);
    assert_eq!(indexed.live_indexes, 0);
    writeln!(std::io::stdout().lock(), "LEDGER_VALIDATION_INDEX_COST {}", serde_json::json!({
        "operations": 1024, "rows": 3072, "indexed_comparisons": indexed.comparisons,
        "original_comparisons": original.comparisons, "indexed_ns": indexed_elapsed.as_nanos(),
        "original_ns": original_elapsed.as_nanos(), "index_capacity": indexed.capacity,
        "index_heap_bytes": indexed.heap_bytes, "bitmap_bytes": indexed.bitmap_bytes,
        "entry_capacity": ledger.entries.capacity(), "operation_capacity": ledger.operations.capacity(),
        "intent_boxes": 1024, "intent_box_bytes": 1024 * size_of::<AuditOperationHandle>(),
        "timing_qualification": false,
        "layouts": {"ledger": size_of::<LedgerState>(), "entry": size_of::<LedgerEntry>(),
            "payload": size_of::<EntryPayload>(), "operation": size_of::<LedgerOperation>(),
            "handle": size_of::<AuditOperationHandle>(), "handle_body": size_of::<HandleBody>(),
            "operation_state": size_of::<AuditOperationState>(), "projected_event": size_of::<ProjectedAuditEvent>(),
            "continuity": size_of::<ContinuityState>(), "signed_row": size_of::<SignedAuditRow>(),
            "key_transition": size_of::<crate::audit_authority::continuity::AuditKeyTransition>(),
            "vector_header": size_of::<Vec<LedgerOperation>>()}
    })).unwrap();
}

#[test]
fn validation_index_accounts_for_malformed_maximum_and_fallible_reservation() {
    let mut ledger = empty();
    let operation = handle(0, ManagementAuditOutcomeCode::Intent);
    for _ in 0..MAX_LEDGER_EVENTS {
        ledger
            .append(&key(), EntryPayload::Intent(Box::new(operation.clone())))
            .unwrap();
    }
    let probe = validation_probe::Probe::start(None);
    assert_eq!(
        ledger.validate(&key(), identity()),
        Err(AuditAuthorityError::BindingMismatch)
    );
    let actual = probe.counts();
    assert_eq!(actual.capacity, MAX_LEDGER_EVENTS);
    assert_eq!(actual.intents, MAX_LEDGER_EVENTS);
    assert_eq!(
        actual.heap_bytes,
        2 * size_of::<usize>() * MAX_LEDGER_EVENTS
    );
    assert_eq!(actual.bitmap_bytes, 512);
    assert_eq!(actual.live_indexes, 0);
    writeln!(
        std::io::stdout().lock(),
        "LEDGER_VALIDATION_INDEX_MALFORMED intents={} capacity={} heap_bytes={} bitmap_bytes={}",
        actual.intents,
        actual.capacity,
        actual.heap_bytes,
        actual.bitmap_bytes
    )
    .unwrap();
    drop(probe);
    let original = completed(1);
    let probe = validation_probe::Probe::start(Some(0));
    assert_eq!(
        original.validate(&key(), identity()),
        Err(AuditAuthorityError::Unavailable)
    );
    assert!(probe.injected());
    assert_eq!(probe.counts().live_indexes, 0);
    drop(probe);
    equivalent(
        &original,
        Ok(()),
        "allocation failure leaves original state valid",
    );
    assert_eq!(
        validation_index::ValidationIndex::overflowing_reservation(),
        Err(AuditAuthorityError::Unavailable)
    );
    let probe = validation_probe::Probe::start(Some(0));
    empty().validate(&key(), identity()).unwrap();
    assert!(!probe.injected());
    assert_eq!(probe.counts().reserves, 0);
}

fn stored(ledger: Option<LedgerState>) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE config_raft_management_audit (singleton INTEGER PRIMARY KEY, state_json BLOB, state_hmac BLOB); CREATE TABLE config_raft_identity (singleton INTEGER PRIMARY KEY, cluster_id BLOB, configuration_id BLOB, configuration_epoch INTEGER);").unwrap();
    conn.execute(
        "INSERT INTO config_raft_identity VALUES (1,?1,?2,?3)",
        rusqlite::params![
            identity().cluster_id().as_bytes().as_slice(),
            identity().configuration_id().as_bytes().as_slice(),
            1_i64
        ],
    )
    .unwrap();
    crate::consensus::write_sync(&conn, &key(), identity(), ledger, true).unwrap();
    conn
}

fn stored_bytes(conn: &rusqlite::Connection) -> (Vec<u8>, Vec<u8>) {
    conn.query_row(
        "SELECT state_json,state_hmac FROM config_raft_management_audit WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

#[test]
fn validation_index_allocation_failure_precedes_native_write_and_receipt() {
    use crate::consensus::ConfigMutationIntent;
    use crate::consensus::{applied_receipt_sync, apply_sync, read_sync, AuditCommand};

    let conn = stored(Some(completed(1)));
    let before = stored_bytes(&conn);
    let command = AuditCommand::Intent(handle(7, ManagementAuditOutcomeCode::Intent));
    for after in [0, 1] {
        let probe = validation_probe::Probe::start(Some(after));
        assert!(
            apply_sync(&conn, &key(), identity(), &command, 110, None).is_err(),
            "scratch failure must be an outer I/O failure, not a replicated rejection"
        );
        assert!(probe.injected());
        assert_eq!(probe.counts().reserves, after + 1);
        assert_eq!(probe.counts().live_indexes, 0);
        assert_eq!(
            stored_bytes(&conn),
            before,
            "pre-read/post-mutation failure cannot publish a row"
        );
    }
    let probe = validation_probe::Probe::start(Some(0));
    assert!(read_sync(&conn, &key(), identity()).is_err());
    assert!(probe.injected());
    drop(probe);
    let intent = ConfigMutationIntent::ManagementAudit(Box::new(AuditCommand::Terminal(handle(
        0,
        ManagementAuditOutcomeCode::Intent,
    ))));
    let probe = validation_probe::Probe::start(Some(0));
    assert!(applied_receipt_sync(&conn, &key(), identity(), &intent).is_err());
    assert!(probe.injected());
    assert_eq!(stored_bytes(&conn), before);
    drop(probe);
    assert_eq!(
        apply_sync(&conn, &key(), identity(), &command, 110, None).unwrap(),
        Ok(())
    );
    assert_ne!(stored_bytes(&conn), before);
    let conn = stored(None);
    let probe = validation_probe::Probe::start(Some(0));
    let initial = empty();
    assert_eq!(
        apply_sync(
            &conn,
            &key(),
            identity(),
            &AuditCommand::Initialize {
                projection: initial.projection,
                limits: initial.limits
            },
            110,
            None
        )
        .unwrap(),
        Ok(())
    );
    assert!(!probe.injected());
    assert_eq!(probe.counts().reserves, 0);
}
