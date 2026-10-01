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

// Diagnostic component measurements only. These elapsed observations do not
// qualify RPC timing or identify a cause by removing any production work.
fn measured_phase<T>(
    phases: &mut std::collections::BTreeMap<&'static str, u128>,
    name: &'static str,
    operation: impl FnOnce() -> T,
) -> T {
    let started = std::time::Instant::now();
    let result = operation();
    assert!(phases.insert(name, started.elapsed().as_nanos()).is_none());
    result
}

#[derive(Default)]
struct FragmentCounts {
    writes: usize,
    bytes: usize,
    maximum_write: usize,
}

impl std::io::Write for FragmentCounts {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writes += 1;
        self.bytes += bytes.len();
        self.maximum_write = self.maximum_write.max(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn config_capacity_957_ledger_read_write_phase_diagnostic() {
    use std::io::Write;

    for completed_operations in [0_u64, 1_023] {
        let fixture_started = std::time::Instant::now();
        let (key, stored) =
            super::config_capacity_957_ledger_allocations::fixture(completed_operations, true);
        let fixture_ns = fixture_started.elapsed().as_nanos();
        let identity = stored.identity;
        let ledger = stored.ledger.as_ref().expect("authenticated fixture");
        let rows_before = completed_operations as usize * 3 + 1;
        let operations = completed_operations as usize + 1;
        assert_eq!(ledger.entries.len(), rows_before);
        assert_eq!(ledger.operations.len(), operations);
        assert!(ledger.continuity.is_none());
        assert!(ledger.operations[..operations - 1]
            .iter()
            .all(|operation| operation.terminal_recorded));
        assert_eq!(
            ledger.operations.last().unwrap().state,
            AuditOperationState::Intent
        );

        // Keep the pre-existing whole-value byte/MAC oracles outside the
        // measured path. The diagnostic never skips authentication.
        let original = serde_json::to_vec(&stored).expect("original canonical bytes");
        let original_mac =
            authenticate(&key, STATE_DOMAIN, &stored).expect("original authenticated transcript");
        let (production, production_mac) =
            encode_state(&stored, &key).expect("actual production state encoding");
        assert!(production == original);
        assert!(production_mac == original_mac);
        drop(production);
        drop(stored);

        // These are the actual functions used by read_verified_sync, in order.
        // SQL I/O, native command/effect work, callbacks, and network scheduling
        // are outside this component diagnostic and must be measured separately.
        let mut phases = std::collections::BTreeMap::new();
        let mut decoded = measured_phase(&mut phases, "read_decode", || {
            ledger_decode::decode(&original).expect("actual retained decoder")
        });
        let read_length = measured_phase(&mut phases, "read_canonical_count", || {
            canonical_state_len(&decoded).expect("actual canonical count")
        });
        assert_eq!(read_length, original.len());
        measured_phase(&mut phases, "read_stream_hmac_verify", || {
            stream_state(&decoded, &key, read_length, None)
                .expect("actual read authentication stream")
                .verify_slice(&original_mac)
                .expect("verify unchanged original MAC");
        });
        measured_phase(&mut phases, "read_indexed_validation", || {
            decoded
                .ledger
                .as_ref()
                .unwrap()
                .validate(&key, identity)
                .expect("full production ledger validation");
        });
        measured_phase(&mut phases, "read_continuity_validation", || {
            decoded
                .ledger
                .as_ref()
                .unwrap()
                .validate_continuity(None)
                .expect("unchanged no-continuity validation");
        });
        assert_eq!(decoded.identity, identity);
        let selected = decoded
            .ledger
            .as_ref()
            .unwrap()
            .operations
            .last()
            .unwrap()
            .handle
            .clone();
        measured_phase(&mut phases, "resolve_selected_outcome", || {
            decoded
                .ledger
                .as_mut()
                .unwrap()
                .resolve(
                    &key,
                    &selected,
                    AuditOperationState::Committed { version: 2 },
                )
                .expect("real selected outcome transition");
        });
        let ledger = decoded.ledger.as_ref().unwrap();
        assert_eq!(ledger.entries.len(), rows_before + 1);
        assert_eq!(ledger.operations.len(), operations);

        // These are the count/reserve/write operations in encode_state, which
        // precede the native LedgerWrite callback. No production step is removed.
        let write_length = measured_phase(&mut phases, "write_canonical_count", || {
            canonical_state_len(&decoded).expect("actual updated canonical count")
        });
        let mut output = measured_phase(&mut phases, "write_output_reserve", || {
            let mut output = Vec::new();
            output
                .try_reserve_exact(write_length)
                .expect("bounded production output capacity");
            output
        });
        let output_mac: [u8; 32] = measured_phase(&mut phases, "write_stream_output_hmac", || {
            stream_state(&decoded, &key, write_length, Some(&mut output))
                .expect("actual output and authentication stream")
                .finalize()
                .into_bytes()
                .into()
        });

        // Independently verify the populated output with both original and
        // current encoders. Neither elapsed value is a pass/fail threshold.
        let after_original = serde_json::to_vec(&decoded).expect("original updated bytes");
        let after_original_mac =
            authenticate(&key, STATE_DOMAIN, &decoded).expect("original updated authentication");
        let (after_production, after_production_mac) =
            encode_state(&decoded, &key).expect("complete actual updated encoder");
        assert_eq!(output.len(), write_length);
        assert!(output == after_original && output == after_production);
        assert!(output_mac == after_original_mac && output_mac == after_production_mac);
        decoded
            .ledger
            .as_ref()
            .unwrap()
            .validate(&key, identity)
            .expect("complete resulting ledger remains valid");

        // Count serde write fragments separately, so counter overhead is never
        // included in a production-phase elapsed observation.
        let mut fragments = FragmentCounts::default();
        serde_json::to_writer(&mut fragments, &decoded).expect("fragment inventory");
        assert_eq!(fragments.bytes, write_length);
        writeln!(
            std::io::stdout().lock(),
            "CONFIG_CAPACITY_LEDGER_PHASE_DIAGNOSTIC {}",
            serde_json::json!({
                "completed_operations": completed_operations,
                "operations": operations,
                "rows_before": rows_before,
                "rows_after": rows_before + 1,
                "read_bytes": read_length,
                "write_bytes": write_length,
                "fixture_build_ns": fixture_ns,
                "phase_ns": phases,
                "output_serde_writes": fragments.writes,
                "output_maximum_write_bytes": fragments.maximum_write,
                "original_bytes_and_mac_equal": true,
                "production_bytes_and_mac_equal": true,
                "timing_qualification": false,
                "causal_removal_evidence": false,
                "native_rpc_qualification": false,
                "test_cfg_observation_hooks_present": true
            })
        )
        .unwrap();
    }
}
