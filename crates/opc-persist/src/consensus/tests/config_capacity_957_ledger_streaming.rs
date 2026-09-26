//! Compatibility controls for bounded canonical ledger authentication.
//! These are in-memory encoder/read controls, not native storage qualification.

use super::*;
use crate::audit_authority::ledger::authenticate;
use crate::audit_authority::{AuditPrivacyKey, AuditPrivacyProjection, AuditPrivacyPurpose};

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        crate::ConfigConsensusClusterId::from_bytes([0xC1; 32]),
        crate::ConfigConsensusConfigurationId::from_bytes([0xC2; 32]),
        crate::ConfigConsensusConfigurationEpoch::new(1).expect("synthetic epoch"),
    )
}

#[test]
fn config_capacity_957_streamed_ledger_authentication_matches_original() {
    let key = AuditKey::new([0xC3; 32]).expect("synthetic authentication key");
    let privacy = AuditPrivacyKey::new([0xC4; 32]).expect("synthetic projection key");
    let projection = privacy
        .project(AuditPrivacyPurpose::KeyIdentity, &[])
        .expect("actual key projection");
    for active in [false, true] {
        let stored = StoredLedger {
            identity: identity(),
            ledger: active.then(|| {
                LedgerState::new(
                    identity(),
                    projection,
                    AuditLedgerLimits::new(4096, 1024).expect("existing ledger limits"),
                )
            }),
        };
        let original_bytes = serde_json::to_vec(&stored).expect("original canonical encoder");
        let original_mac =
            authenticate(&key, STATE_DOMAIN, &stored).expect("original authenticator");
        let (encoded, mac) = encode_state(&stored, &key).expect("streamed state encoding");
        assert!(encoded == original_bytes, "retained JSON bytes stay exact");
        assert!(mac == original_mac, "authenticated transcript stays exact");
        let length = canonical_state_len(&stored).expect("count canonical JSON");
        assert_eq!(length, original_bytes.len());
        stream_state(&stored, &key, length, None)
            .expect("stream without output allocation")
            .verify_slice(&original_mac)
            .expect("original authenticator verifies");
    }
}

#[test]
fn config_capacity_957_streamed_ledger_read_preserves_canonical_verification() {
    let key = AuditKey::new([0xC3; 32]).expect("synthetic authentication key");
    let identity = identity();
    let connection = Connection::open_in_memory().expect("unit SQL control");
    connection
        .execute_batch(
            "CREATE TABLE config_raft_management_audit \
             (singleton INTEGER PRIMARY KEY, state_json BLOB, state_hmac BLOB); \
             CREATE TABLE config_raft_identity \
             (singleton INTEGER PRIMARY KEY, cluster_id BLOB, configuration_id BLOB, configuration_epoch INTEGER);",
        )
        .expect("minimal encoder control tables");
    connection
        .execute(
            "INSERT INTO config_raft_identity VALUES (1, ?1, ?2, ?3)",
            params![
                identity.cluster_id().as_bytes().as_slice(),
                identity.configuration_id().as_bytes().as_slice(),
                identity.configuration_epoch().get() as i64,
            ],
        )
        .expect("exact authority identity");
    initialize_sync(&connection, &key, identity).expect("inactive authenticated row");
    let (encoded, mac): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("original row");
    // The existing format authenticates parsed canonical JSON. Valid external
    // whitespace must remain readable with the original MAC; hashing the raw
    // SQL bytes would silently change that compatibility contract.
    let mut spaced = b" \n\r\t".to_vec();
    spaced.extend_from_slice(&encoded);
    spaced.extend_from_slice(b"\n\t ");
    connection
        .execute(
            "UPDATE config_raft_management_audit SET state_json=?1 WHERE singleton=1",
            params![&spaced],
        )
        .expect("noncanonical whitespace control");
    assert!(read_sync(&connection, &key, identity)
        .expect("canonical authentication accepts external whitespace")
        .is_none());
    let unchanged: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("readback after verification");
    assert!(
        unchanged.0 == spaced && unchanged.1 == mac,
        "read has no effects"
    );

    let mut tampered_mac = mac.clone();
    tampered_mac[0] ^= 1;
    connection
        .execute(
            "UPDATE config_raft_management_audit SET state_hmac=?1 WHERE singleton=1",
            params![tampered_mac],
        )
        .expect("tampered authentication control");
    assert!(read_sync(&connection, &key, identity).is_err());
    connection
        .execute(
            "UPDATE config_raft_management_audit SET state_json=?1, state_hmac=?2 WHERE singleton=1",
            params![encoded, mac],
        )
        .expect("restore exact original row");
    assert!(read_sync(&connection, &key, identity)
        .expect("original row remains readable")
        .is_none());
    let other_key = AuditKey::new([0xC5; 32]).expect("distinct synthetic key");
    assert!(read_sync(&connection, &other_key, identity).is_err());
}
