use opc_key::{ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::AuditedConfigEffect;
use crate::consensus::types::*;
use crate::*;

pub(crate) fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("encoding-fixture").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([3; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

pub(crate) fn key() -> AuditKey {
    AuditKey::new([4; 32]).unwrap()
}

pub(crate) fn timestamp() -> Timestamp {
    "2026-01-01T00:00:00.123456789Z".parse().unwrap()
}

pub(crate) fn tx() -> TxId {
    "11111111-1111-4111-8111-111111111111".parse().unwrap()
}

pub(crate) fn parent() -> TxId {
    "22222222-2222-4222-8222-222222222222".parse().unwrap()
}

pub(crate) fn aad(record: &CommitRecord, store: &str) -> EnvelopeAad {
    EnvelopeAad::config(
        TenantId::from_static("default"),
        record.version.get(),
        ConfigAad::new(
            record.tx_id,
            record.parent_tx_id,
            record.committed_at,
            &record.principal,
            record.schema_digest,
            store,
        )
        .unwrap(),
    )
}

pub(crate) fn handle_key() -> KeyHandle {
    KeyHandle::new(
        KeyId::new("synthetic-key").unwrap(),
        KeyPurpose::Config,
        TenantId::from_static("default"),
        Zeroizing::new([0x31; 32]),
    )
}

pub(crate) fn record() -> CommitRecord {
    let mut record = CommitRecord {
        tx_id: tx(),
        parent_tx_id: Some(parent()),
        version: ConfigVersion::new(2),
        committed_at: timestamp(),
        principal: "writer".into(),
        source: CommitSource::Netconf,
        schema_digest: SchemaDigest::from_bytes([0x32; 32]),
        plaintext_digest: Sha256::digest(b"null").to_vec(),
        encrypted_blob: Vec::new(),
        rollback_point: true,
        confirmed_deadline: None,
    };
    record.encrypted_blob = opc_crypto::encrypt_envelope_with_handle_and_nonce(
        &handle_key(),
        &aad(&record, "running"),
        b"null",
        [0x33; 12],
    )
    .unwrap();
    record
}

pub(crate) fn audit() -> Vec<AuditRecord> {
    vec![AuditRecord {
        tx_id: tx(),
        sequence: 0,
        yang_path: "/fixture:items/item[name='synthetic']/value".into(),
        op_type: AuditOpType::Replace,
        previous_value: Some("123".into()),
        new_value: Some("456".into()),
        redaction_applied: false,
        previous_hash: [0; 32],
        entry_hmac: [0; 32],
    }]
}

pub(crate) fn prepared() -> PreparedConfigCommit {
    PreparedConfigCommit::prepare(record(), audit(), &key()).unwrap()
}

pub(crate) fn handle(effect: Option<&AuditedConfigEffect>) -> AuditOperationHandle {
    let privacy = AuditPrivacyKey::new([5; 32]).unwrap();
    let event = ManagementAuditEventRecord::try_new(
        [6; 16],
        ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
            .unwrap(),
        "synthetic",
        "writer",
        ManagementAuditTransportCode::Gnmi,
        ManagementAuditOperationCode::Update,
        ManagementAuditOutcomeCode::Intent,
        None::<&str>,
        ["/fixture:system/fixture:value"],
        Some("synthetic-transaction"),
    )
    .unwrap();
    let event = ProjectedAuditEvent::project(&privacy, &event).unwrap();
    let binding =
        AuditOperationBinding::project(&privacy, &event, 1, b"synthetic-operation").unwrap();
    AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding,
            event,
            issued_at: 100,
            expires_at: 200,
            nonce: [7; 16],
            key_epoch: 1,
            mutation: effect.map(|effect| effect.digest(&key()).unwrap()),
        },
        &key(),
    )
    .unwrap()
}

pub(crate) fn command(intent: ConfigMutationIntent) -> ConfigConsensusCommand {
    ConfigConsensusCommand {
        schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
        identity: identity(),
        request_id: ConfigConsensusRequestId::from_bytes([8; 16]),
        logical_time: timestamp(),
        intent,
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").unwrap();
    }
    output
}
