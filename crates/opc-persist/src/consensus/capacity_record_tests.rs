//! Format controls only: no storage, transport or allocation qualification.

use super::*;
use crate::types::CommitSource;
use opc_crypto::{
    encrypt_attested_envelope_with_handle_and_nonce,
    encrypt_bounded_config_envelope_with_handle_and_nonce,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;
const MAGIC: &[u8] = b"\x89OPCCFG\x02\r\n\x1a\n";

fn identity(cluster: u8, configuration: u8, epoch: u64) -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        super::super::types::ConfigConsensusClusterId::from_bytes([cluster; 32]),
        super::super::types::ConfigConsensusConfigurationId::from_bytes([configuration; 32]),
        super::super::types::ConfigConsensusConfigurationEpoch::new(epoch).expect("epoch"),
    )
}

fn scope() -> ConfigConsensusIdentity {
    identity(0xA1, 0xA2, 3)
}

fn key() -> AuditKey {
    AuditKey::new_with_epoch([0xA3; 32], 4).expect("synthetic audit key")
}

fn plaintext(logical: usize, replay: usize) -> Vec<u8> {
    let mut config = vec![b'q'; logical];
    if logical == 1 {
        config[0] = b'0';
    } else {
        config[0] = b'"';
        config[logical - 1] = b'"';
    }
    if replay == 0 {
        return config;
    }
    let mut framed = MAGIC.to_vec();
    framed.extend_from_slice(b"{\"config\":");
    framed.extend_from_slice(&config);
    framed.extend_from_slice(b",\"idempotency_key\":\"");
    let padding = replay
        .checked_sub(framed.len() - logical + 2)
        .expect("framing budget");
    framed.resize(framed.len() + padding, b'r');
    framed.extend_from_slice(b"\"}");
    assert_eq!(framed.len(), logical + replay);
    framed
}

fn fixture(logical: usize, replay: usize, bounded: bool) -> AttestedConfigCommit {
    let tx_id: TxId = "a4a4a4a4-a4a4-4a4a-8a4a-a4a4a4a4a4a4"
        .parse()
        .expect("synthetic tx");
    let parent_tx_id: TxId = "a5a5a5a5-a5a5-4a5a-8a5a-a5a5a5a5a5a5"
        .parse()
        .expect("synthetic parent");
    let version = ConfigVersion::new(7);
    let committed_at = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp_nanos(1_800_000_000_123_456_789)
            .expect("synthetic timestamp"),
    );
    let principal =
        "spiffe://qualification.invalid/tenant/test/ns/test/sa/config/nf/test/instance/0";
    let schema_digest = SchemaDigest::from_bytes([0xA6; 32]);
    let aad = opc_key::EnvelopeAad::config(
        TenantId::from_static("test"),
        version.get(),
        opc_key::ConfigAad::new(
            tx_id,
            Some(parent_tx_id),
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .expect("synthetic AAD"),
    );
    let handle = opc_key::KeyHandle::new(
        opc_key::KeyId::new("capacity-record-proof").expect("synthetic key ID"),
        opc_key::KeyPurpose::Config,
        TenantId::from_static("test"),
        opc_key::Zeroizing::new([0xA7; 32]),
    );
    let plaintext = plaintext(logical, replay);
    let envelope = if bounded {
        encrypt_bounded_config_envelope_with_handle_and_nonce(&handle, &aad, &plaintext, [0xA8; 12])
            .expect("bounded encryption")
    } else {
        encrypt_attested_envelope_with_handle_and_nonce(&handle, &aad, &plaintext, [0xA8; 12])
            .expect("legacy encryption")
    };
    AttestedConfigCommit::try_new(
        CommitRecord {
            tx_id,
            parent_tx_id: Some(parent_tx_id),
            version,
            committed_at,
            principal: principal.to_owned(),
            source: CommitSource::Gnmi,
            schema_digest,
            plaintext_digest: Sha256::digest(&plaintext).to_vec(),
            encrypted_blob: envelope.encoded().to_vec(),
            rollback_point: false,
            confirmed_deadline: None,
        },
        Vec::new(),
        envelope.claim().expect("one-shot claim"),
    )
    .expect("paired authenticated record")
}

fn signed_test_counts(record: &CommitRecord, logical: u32, replay: u32) -> CapacityRecordBinding {
    // Deliberately bypass the private issuer in this white-box negative only.
    // A valid MAC must not exempt future incoming records from fixed bounds.
    let mut proof = CapacityRecordBinding {
        header: [0; HEADER_BYTES],
        tag: [0; 32],
    };
    proof.header[..4].copy_from_slice(&[0, 1, 0, 1]);
    proof.header[4..8].copy_from_slice(&logical.to_be_bytes());
    proof.header[8..12].copy_from_slice(&replay.to_be_bytes());
    proof.tag = proof
        .mac(record, scope(), &key())
        .expect("test MAC")
        .finalize()
        .into_bytes()
        .into();
    proof
}

#[test]
fn config_capacity_957_record_proof_requires_paired_bounded_evidence() {
    let legacy = fixture(32, 0, false);
    assert!(CapacityRecordBinding::issue(&legacy, scope(), &key(), PROFILE).is_err());
    let bounded = fixture(32, 0, true);
    assert!(
        CapacityRecordBinding::issue(&bounded, scope(), &key(), ConfigCapacityProfile::Legacy,)
            .is_err()
    );
    let proof = CapacityRecordBinding::issue(&bounded, scope(), &key(), PROFILE).expect("issue");
    proof
        .verify(bounded.record(), scope(), &key(), PROFILE)
        .expect("same exact record");
    assert_eq!(proof.encode().len(), 44);
    assert_eq!(
        &proof.encode()[..12],
        &[0, 1, 0, 1, 0, 0, 0, 32, 0, 0, 0, 0]
    );
    assert_eq!(format!("{proof:?}"), "CapacityRecordBinding(<redacted>)");
    let decoded = CapacityRecordBinding::decode(&proof.encode()).expect("exact fixed encoding");
    assert_eq!(decoded, proof);
    decoded
        .verify(bounded.record(), scope(), &key(), PROFILE)
        .expect("authenticated decode");
    for size in [0, 12, 32, 43, 45, 64] {
        assert!(CapacityRecordBinding::decode(&vec![0; size]).is_err());
    }
    let json = serde_json::to_vec(&proof).expect("new private JSON field");
    let json_proof: CapacityRecordBinding = serde_json::from_slice(&json).expect("new JSON field");
    assert_eq!(json_proof, proof);
    let wire = opc_consensus::encode_bounded(&proof).expect("actual postcard field");
    assert_eq!(wire, proof.encode());
    let wire_proof: CapacityRecordBinding =
        opc_consensus::decode_bounded(&wire).expect("actual postcard reader");
    assert_eq!(wire_proof, proof);
    let mut trailing = wire;
    trailing.push(0);
    assert!(opc_consensus::decode_bounded::<CapacityRecordBinding>(&trailing).is_err());
}

#[test]
fn config_capacity_957_record_proof_accepts_joint_logical_and_replay_limits() {
    let bounded = fixture(
        CONFIG_CAPACITY_V1_LOGICAL_BYTES,
        CONFIG_CAPACITY_V1_REPLAY_BYTES,
        true,
    );
    let proof = CapacityRecordBinding::issue(&bounded, scope(), &key(), PROFILE).expect("at limit");
    assert_eq!(
        &proof.encode()[4..8],
        &(CONFIG_CAPACITY_V1_LOGICAL_BYTES as u32).to_be_bytes()
    );
    assert_eq!(
        &proof.encode()[8..12],
        &(CONFIG_CAPACITY_V1_REPLAY_BYTES as u32).to_be_bytes()
    );
    proof
        .verify(bounded.record(), scope(), &key(), PROFILE)
        .expect("both exact limits");
}

#[test]
fn config_capacity_957_record_proof_rejects_each_corrupted_byte() {
    let bounded = fixture(32, 64, true);
    let proof = CapacityRecordBinding::issue(&bounded, scope(), &key(), PROFILE).expect("issue");
    for offset in 0..44 {
        let mut encoded = proof.encode();
        encoded[offset] ^= 1;
        let changed = CapacityRecordBinding::decode(&encoded).expect("same fixed length");
        assert!(
            changed
                .verify(bounded.record(), scope(), &key(), PROFILE)
                .is_err(),
            "changed proof field must reject"
        );
    }
}

#[test]
fn config_capacity_957_record_proof_rejects_cross_authority_key_and_profile() {
    let bounded = fixture(32, 0, true);
    let proof = CapacityRecordBinding::issue(&bounded, scope(), &key(), PROFILE).expect("issue");
    for other in [
        identity(0xB1, 0xA2, 3),
        identity(0xA1, 0xB2, 3),
        identity(0xA1, 0xA2, 4),
    ] {
        assert!(proof
            .verify(bounded.record(), other, &key(), PROFILE)
            .is_err());
    }
    for other in [
        AuditKey::new_with_epoch([0xB3; 32], 4).expect("other material"),
        AuditKey::new_with_epoch([0xA3; 32], 5).expect("other epoch"),
    ] {
        assert!(proof
            .verify(bounded.record(), scope(), &other, PROFILE)
            .is_err());
    }
    assert!(proof
        .verify(
            bounded.record(),
            scope(),
            &key(),
            ConfigCapacityProfile::Legacy
        )
        .is_err());
}

#[test]
fn config_capacity_957_record_proof_rejects_changed_record_and_digest() {
    let bounded = fixture(32, 64, true);
    let proof = CapacityRecordBinding::issue(&bounded, scope(), &key(), PROFILE).expect("issue");
    let changes: [fn(&mut CommitRecord); 9] = [
        |record| record.tx_id = TxId::new(),
        |record| record.version = ConfigVersion::new(8),
        |record| record.parent_tx_id = None,
        |record| record.principal.push('x'),
        |record| record.schema_digest = SchemaDigest::from_bytes([0xB4; 32]),
        |record| record.plaintext_digest[0] ^= 1,
        |record| *record.encrypted_blob.last_mut().expect("tag byte") ^= 1,
        |record| record.encrypted_blob.push(0),
        |record| {
            record.plaintext_digest.pop();
        },
    ];
    for change in changes {
        let mut record = bounded.record().clone();
        change(&mut record);
        assert!(
            proof.verify(&record, scope(), &key(), PROFILE).is_err(),
            "a proof cannot authorize a different record"
        );
    }
}

#[test]
fn config_capacity_957_record_proof_enforces_independent_bounds_even_with_valid_mac() {
    for (logical, replay) in [
        (CONFIG_CAPACITY_V1_LOGICAL_BYTES + 1, 0),
        (1, CONFIG_CAPACITY_V1_REPLAY_BYTES + 1),
        (
            CONFIG_CAPACITY_V1_LOGICAL_BYTES,
            CONFIG_CAPACITY_V1_REPLAY_BYTES + 1,
        ),
    ] {
        let legacy = fixture(logical, replay, false);
        let proof = signed_test_counts(legacy.record(), logical as u32, replay as u32);
        assert!(
            proof
                .verify(legacy.record(), scope(), &key(), PROFILE)
                .is_err(),
            "valid MAC never bypasses logical or replay limits"
        );
    }
    let bounded = fixture(32, 64, true);
    for (logical, replay) in [(31, 64), (32, 63), (33, 64), (32, 65), (0, 96)] {
        let proof = signed_test_counts(bounded.record(), logical, replay);
        assert!(
            proof
                .verify(bounded.record(), scope(), &key(), PROFILE)
                .is_err(),
            "counts must equal exact AES plaintext length and valid logical framing"
        );
    }
}

#[test]
fn config_capacity_957_record_proof_preserves_original_parent_binding() {
    let bounded = fixture(32, 64, true);
    let proof = CapacityRecordBinding::issue(&bounded, scope(), &key(), PROFILE).expect("issue");
    let mut detached = bounded.record().clone();
    detached.parent_tx_id = None;
    assert!(proof.verify(&detached, scope(), &key(), PROFILE).is_err());
    // Only authenticated history may reconstruct this original parent. This
    // format test is not a retention transaction or snapshot-transfer test.
    detached.parent_tx_id = bounded.record().parent_tx_id;
    proof
        .verify(&detached, scope(), &key(), PROFILE)
        .expect("original AEAD parent");
    detached.rollback_point = true;
    proof
        .verify(&detached, scope(), &key(), PROFILE)
        .expect("separately authenticated mutable SQL projection is not frozen by this proof");
}

#[test]
fn config_capacity_957_record_proof_checks_lengths_before_allocating_key_or_aad() {
    // This exercises only the allocation-free header preflight. It does not
    // describe a 16-byte header as a complete valid encrypted envelope.
    let mut header = [0; 16];
    header[8..10].copy_from_slice(&512_u16.to_be_bytes());
    header[10..12].copy_from_slice(&12_u16.to_be_bytes());
    header[12..16].copy_from_slice(&65_536_u32.to_be_bytes());
    preflight_envelope_lengths(&header).expect("inclusive component limits");
    let mut one_over_key = header;
    one_over_key[8..10].copy_from_slice(&513_u16.to_be_bytes());
    assert!(preflight_envelope_lengths(&one_over_key).is_err());
    let mut one_over_aad = header;
    one_over_aad[12..16].copy_from_slice(&65_537_u32.to_be_bytes());
    assert!(preflight_envelope_lengths(&one_over_aad).is_err());
    for length in [0_u16, 11, 13, u16::MAX] {
        let mut nonce = header;
        nonce[10..12].copy_from_slice(&length.to_be_bytes());
        assert!(preflight_envelope_lengths(&nonce).is_err());
    }
    for len in 0..16 {
        assert!(preflight_envelope_lengths(&header[..len]).is_err());
    }
}

#[test]
fn config_capacity_957_record_proof_checks_borrowed_sql_ciphertext() {
    // This exercises the borrowed proof boundary, not native consensus storage,
    // retention, snapshot transfer, an allocation peak or a production profile.
    let commit = fixture(96 * 1024, 64, true);
    let proof = CapacityRecordBinding::issue(&commit, scope(), &key(), PROFILE).expect("issue");
    let directory = tempfile::tempdir().expect("synthetic proof directory");
    let mut connection = rusqlite::Connection::open(directory.path().join("proof.sqlite"))
        .expect("disk SQL connection");
    connection
        .execute_batch("CREATE TABLE proof_input (ciphertext BLOB NOT NULL, digest BLOB NOT NULL)")
        .expect("synthetic schema");
    connection
        .execute(
            "INSERT INTO proof_input (ciphertext, digest) VALUES (?1, ?2)",
            rusqlite::params![
                &commit.record().encrypted_blob,
                &commit.record().plaintext_digest
            ],
        )
        .expect("synthetic encrypted row");
    let transaction = connection.transaction().expect("pinned transaction");
    {
        let mut statement = transaction
            .prepare("SELECT ciphertext, digest FROM proof_input")
            .expect("borrowed query");
        let mut rows = statement.query([]).expect("borrowed rows");
        let row = rows.next().expect("read").expect("one row");
        let encrypted_blob = row
            .get_ref(0)
            .expect("ciphertext column")
            .as_blob()
            .expect("ciphertext BLOB");
        let plaintext_digest = row
            .get_ref(1)
            .expect("digest column")
            .as_blob()
            .expect("digest BLOB");
        let view = ConfigRecordView {
            encrypted_blob,
            plaintext_digest,
            ..ConfigRecordView::from(commit.record())
        };
        proof
            .verify_borrowed(view, scope(), &key(), PROFILE)
            .expect("exact ciphertext and digest borrowed from pinned row");
        // Neither a borrowed record nor a valid proof supplies scope or the
        // authenticated original parent on behalf of the consuming authority.
        let detached = ConfigRecordView {
            parent_tx_id: None,
            ..view
        };
        assert!(proof
            .verify_borrowed(detached, scope(), &key(), PROFILE)
            .is_err());
        assert!(proof
            .verify_borrowed(view, identity(0xB1, 0xA2, 3), &key(), PROFILE)
            .is_err());
        assert!(proof
            .verify_borrowed(view, scope(), &key(), ConfigCapacityProfile::Legacy)
            .is_err());
        assert!(rows.next().expect("row end").is_none());
    }
    transaction.rollback().expect("end pinned read");
    // A same-sized changed digest cannot become acceptable by entering through
    // the borrowed verifier. The original encrypted envelope remains exact.
    connection
        .execute("UPDATE proof_input SET digest = zeroblob(32)", [])
        .expect("synthetic changed digest");
    let transaction = connection.transaction().expect("second pinned transaction");
    {
        let mut statement = transaction
            .prepare("SELECT ciphertext, digest FROM proof_input")
            .expect("changed query");
        let mut rows = statement.query([]).expect("changed rows");
        let row = rows.next().expect("read").expect("one changed row");
        let view = ConfigRecordView {
            encrypted_blob: row
                .get_ref(0)
                .expect("ciphertext column")
                .as_blob()
                .expect("ciphertext BLOB"),
            plaintext_digest: row
                .get_ref(1)
                .expect("digest column")
                .as_blob()
                .expect("digest BLOB"),
            ..ConfigRecordView::from(commit.record())
        };
        assert!(proof
            .verify_borrowed(view, scope(), &key(), PROFILE)
            .is_err());
    }
    transaction.rollback().expect("end changed pinned read");
}
