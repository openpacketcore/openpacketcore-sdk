#![allow(dead_code, unused_imports)]
use opc_persist::{AuditKey, AuditOpType, AuditRecord, CommitRecord, CommitSource};
use opc_types::{SchemaDigest, Timestamp, TxId};

pub fn make_commit_record(tx_id: TxId, version: u64) -> CommitRecord {
    CommitRecord {
        tx_id,
        parent_tx_id: None,
        version: opc_types::ConfigVersion::new(version),
        committed_at: Timestamp::now_utc(),
        principal: "spiffe://test/trust-domain/tenant/test/ns/default/sa/svc/nf/test/instance/1"
            .to_string(),
        source: CommitSource::LocalOperator,
        schema_digest: SchemaDigest::from_bytes([0u8; 32]),
        plaintext_digest: vec![],
        encrypted_blob: b"test encrypted blob".to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    }
}

pub fn make_audit_record(tx_id: TxId, sequence: u32, path: &str) -> AuditRecord {
    AuditRecord {
        tx_id,
        sequence,
        yang_path: path.to_string(),
        op_type: AuditOpType::Create,
        previous_value: None,
        new_value: Some(r#""value""#.to_string()),
        redaction_applied: false,
        previous_hash: [0u8; 32],
        entry_hmac: [0u8; 32],
    }
}

pub fn test_audit_key() -> AuditKey {
    AuditKey::new([0x42; 32]).expect("test audit key is non-zero")
}

pub fn make_audit_record_with_op(
    tx_id: TxId,
    sequence: u32,
    path: &str,
    op: AuditOpType,
) -> AuditRecord {
    AuditRecord {
        tx_id,
        sequence,
        yang_path: path.to_string(),
        op_type: op,
        previous_value: None,
        new_value: Some(r#""v""#.to_string()),
        redaction_applied: false,
        previous_hash: [0u8; 32],
        entry_hmac: [0u8; 32],
    }
}
