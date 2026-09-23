//! Real preparation controls for an impossible finalized audit batch.
//! The observer counts only finalized path String capacities, not transferred
//! input buffers, allocator overhead, HMAC temporaries or a whole operation.

use std::cell::Cell;

use super::*;
use crate::types::{AuditOpType, CommitSource};
use opc_consensus::{AppendEntriesBatchAccumulator, DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES};
use opc_types::{ConfigVersion, SchemaDigest, TenantId};

#[derive(Clone, Copy, Default)]
struct Observed {
    reached: bool,
    paths: usize,
    capacity: usize,
}

thread_local! {
    static OBSERVED: Cell<Observed> = const { Cell::new(Observed {
        reached: false, paths: 0, capacity: 0,
    }) };
}

pub(super) fn observe_start() {
    OBSERVED.set(Observed {
        reached: true,
        ..Observed::default()
    });
}

pub(super) fn observe_path(capacity: usize) {
    OBSERVED.with(|observed| {
        let mut value = observed.get();
        value.paths += 1;
        value.capacity += capacity;
        observed.set(value);
    });
}

fn encoded_size(value: &impl Serialize) -> usize {
    let mut counter = AppendEntriesBatchAccumulator::new();
    counter.consider(value).expect("actual postcard size");
    counter.serialized_entry_bytes()
}

fn key() -> crate::AuditKey {
    crate::AuditKey::new([0x81; 32]).expect("synthetic audit key")
}

fn record() -> CommitRecord {
    let tx_id = TxId::new();
    let version = ConfigVersion::new(1);
    let committed_at = Timestamp::now_utc();
    let principal =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0";
    let schema_digest = SchemaDigest::from_bytes([0x82; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version.get(),
        opc_key::ConfigAad::new(
            tx_id,
            None,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("capacity-audit-preparation").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0x83; 32]),
    );
    let envelope = opc_crypto::encrypt_attested_envelope_with_handle_and_nonce(
        &handle, &aad, b"0", [0x84; 12],
    )
    .expect("real synthetic encrypted envelope");
    CommitRecord {
        tx_id,
        parent_tx_id: None,
        version,
        committed_at,
        principal: principal.to_owned(),
        source: CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest(b"0").to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    }
}

fn entry(tx_id: TxId, sequence: u32, path: String) -> AuditRecord {
    AuditRecord {
        tx_id,
        sequence,
        yang_path: path,
        op_type: AuditOpType::Update,
        previous_value: Some(REDACTED_AUDIT_VALUE.to_owned()),
        new_value: Some(REDACTED_AUDIT_VALUE.to_owned()),
        redaction_applied: true,
        previous_hash: [0; 32],
        entry_hmac: [0; 32],
    }
}

fn at_encoded_size(tx_id: TxId, target: usize) -> Vec<AuditRecord> {
    let mut audit = Vec::new();
    while encoded_size(&audit) < target {
        audit.push(entry(
            tx_id,
            audit.len() as u32,
            format!("/{}", "x".repeat(CONFIG_AUDIT_PATH_MAX_BYTES - 1)),
        ));
    }
    let excess = encoded_size(&audit) - target;
    let last = audit.last_mut().expect("nonempty synthetic audit");
    assert!(excess < last.yang_path.len() - 1);
    last.yang_path.truncate(last.yang_path.len() - excess);
    // This fixture stays on the same postcard string-length varint width.
    assert_eq!(encoded_size(&audit), target);
    audit
}

fn prepare(
    record: CommitRecord,
    audit: Vec<AuditRecord>,
) -> (Result<PreparedConfigCommit, PersistError>, Observed) {
    OBSERVED.set(Observed::default());
    let result = PreparedConfigCommit::prepare(record, audit, &key());
    let observed = OBSERVED.get();
    assert!(
        observed.reached,
        "real preparation reached the allocation observer"
    );
    eprintln!(
        "CONFIG_CAPACITY_AUDIT_PREPARATION finalized_paths={} output_capacity={}",
        observed.paths, observed.capacity
    );
    (result, observed)
}

#[test]
fn config_capacity_957_audit_component_at_ceiling_keeps_its_encoding() {
    let record = record();
    let audit = at_encoded_size(record.tx_id, DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES);
    let (result, observed) = prepare(record, audit);
    let prepared =
        result.expect("audit component alone fits; complete command still has its own fence");
    assert_eq!(
        encoded_size(&prepared.audit),
        DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES
    );
    assert_eq!(observed.paths, prepared.audit.len());
    assert!(observed.capacity > 0);
    prepared.validate().expect("same valid finalized audit");
    // Do not claim command admission from this component-only boundary.
    let intent = ConfigMutationIntent::AppendCommit(Box::new(prepared));
    assert!(encoded_size(&intent) > DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES);
}

#[test]
fn config_capacity_957_audit_one_over_rejects_before_finalized_allocation() {
    let record = record();
    let audit = at_encoded_size(
        record.tx_id,
        DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES + 1,
    );
    let (result, observed) = prepare(record, audit);
    assert_eq!(
        observed.capacity, 0,
        "impossible audit batch allocated finalized paths before rejection"
    );
    assert_eq!(observed.paths, 0);
    assert!(
        result.is_err(),
        "audit component exceeding the complete command fence must reject"
    );
}

#[test]
fn config_capacity_957_audit_expansion_rejects_before_finalized_allocation() {
    let record = record();
    // Raw paths fit well below the command ceiling; each redacted path expands
    // to 8,192 bytes. The aggregate finalized audit cannot fit the command.
    let audit: Vec<_> = (0..129)
        .map(|sequence| {
            entry(
                record.tx_id,
                sequence,
                format!("/{}{}", "x".repeat(57), "[key='x']".repeat(98)),
            )
        })
        .collect();
    assert_eq!(
        tokenize_audit_path(&audit[0].yang_path, &key())
            .expect("valid expanded field")
            .len(),
        CONFIG_AUDIT_PATH_MAX_BYTES
    );
    assert!(encoded_size(&audit) < DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES);
    let (result, observed) = prepare(record, audit);
    assert_eq!(
        observed.capacity, 0,
        "expanded impossible audit allocated finalized paths before rejection"
    );
    assert_eq!(observed.paths, 0);
    assert!(result.is_err());
}
