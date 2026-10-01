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

#[derive(Clone, Copy, Default)]
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

struct ObservedWriter<W> {
    inner: W,
    fragments: FragmentCounts,
    last_write: usize,
    flushes: usize,
}

#[derive(Clone, Copy, Default)]
struct AuthenticatedSinkObservation {
    fragments: FragmentCounts,
    last_write: usize,
    output_writes: usize,
    verification_writes: usize,
}

std::thread_local! {
    static AUTHENTICATED_SINK: std::cell::Cell<Option<AuthenticatedSinkObservation>> =
        const { std::cell::Cell::new(None) };
}

// This hook is compiled only with the unit-test module. It observes the actual
// StateWriter used by both production entry points, including a bypass of the
// batching helper. No recorder exists in the native integration-library build.
pub(super) fn observe_authenticated_sink_write(bytes: usize, with_output: bool) {
    AUTHENTICATED_SINK.with(|state| {
        if let Some(mut observed) = state.get() {
            observed.fragments.writes += 1;
            observed.fragments.bytes += bytes;
            observed.fragments.maximum_write = observed.fragments.maximum_write.max(bytes);
            observed.last_write = bytes;
            if with_output {
                observed.output_writes += 1;
            } else {
                observed.verification_writes += 1;
            }
            state.set(Some(observed));
        }
    });
}

fn observe_state_stream<T>(operation: impl FnOnce() -> T) -> (T, AuthenticatedSinkObservation) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            AUTHENTICATED_SINK.with(|state| state.set(None));
        }
    }

    AUTHENTICATED_SINK.with(|state| {
        assert!(
            state.get().is_none(),
            "one scoped sink observation at a time"
        );
        state.set(Some(AuthenticatedSinkObservation::default()));
    });
    let reset = Reset;
    let result = operation();
    let observed = AUTHENTICATED_SINK.with(|state| state.take().expect("active observation"));
    drop(reset);
    (result, observed)
}

impl<W> ObservedWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            fragments: FragmentCounts::default(),
            last_write: 0,
            flushes: 0,
        }
    }
}

impl<W: std::io::Write> std::io::Write for ObservedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.fragments.writes += 1;
        self.fragments.bytes += written;
        self.fragments.maximum_write = self.fragments.maximum_write.max(written);
        self.last_write = written;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        self.inner.flush()
    }
}

#[test]
fn config_capacity_957_streamed_ledger_buffer_preserves_partitions_and_flushes() {
    use std::io::Write;

    let chunk = STATE_STREAM_BUFFER_BYTES;
    for length in [0, 1, chunk - 1, chunk, chunk + 1, 2 * chunk, 2 * chunk + 1] {
        let expected: Vec<u8> = (0..length).map(|index| (index % 251) as u8).collect();
        for partition in [1, 19, chunk - 1, chunk, chunk + 7] {
            let mut observed = ObservedWriter::new(Vec::new());
            {
                let mut buffer = StateBuffer::new(&mut observed);
                assert_eq!(
                    std::mem::size_of_val(&buffer),
                    chunk + 2 * std::mem::size_of::<usize>(),
                    "fixed stack payload plus one reference and one length"
                );
                for fragment in expected.chunks(partition) {
                    buffer.write_all(fragment).expect("partitioned input");
                    assert_eq!(buffer.write(&[]).expect("empty input"), 0);
                }
                buffer.flush().expect("final partial chunk is required");
                assert_eq!(buffer.buffered, 0);
            }
            assert!(observed.inner == expected, "every byte stays in order");
            assert_eq!(observed.fragments.bytes, length);
            assert_eq!(observed.fragments.writes, length.div_ceil(chunk));
            assert_eq!(observed.fragments.maximum_write, length.min(chunk));
            assert_eq!(
                observed.last_write,
                if length == 0 {
                    0
                } else {
                    (length - 1) % chunk + 1
                }
            );
            assert_eq!(observed.flushes, 1);
        }
    }

    let mut observed = ObservedWriter::new(Vec::new());
    {
        let mut buffer = StateBuffer::new(&mut observed);
        buffer.write_all(b"first").expect("first partial chunk");
        buffer.flush().expect("explicit partial flush");
        buffer.write_all(b"second").expect("second partial chunk");
        buffer.flush().expect("second explicit flush");
        buffer.flush().expect("empty flush");
    }
    assert_eq!(observed.inner, b"firstsecond");
    assert_eq!(observed.fragments.writes, 2);
    assert_eq!(observed.flushes, 3);
}

#[test]
fn config_capacity_957_streamed_ledger_buffer_propagates_sink_errors() {
    use std::collections::VecDeque;
    use std::io::Write;

    enum Step {
        Interrupted,
        Partial(usize),
        Failure,
        Zero,
    }
    struct ControlledWriter {
        encoded: Vec<u8>,
        steps: VecDeque<Step>,
        fail_flush: bool,
    }
    impl Write for ControlledWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let accepted = match self.steps.pop_front() {
                Some(Step::Interrupted) => return Err(io::ErrorKind::Interrupted.into()),
                Some(Step::Failure) => return Err(io::Error::other("controlled sink failure")),
                Some(Step::Zero) => return Ok(0),
                Some(Step::Partial(limit)) => limit.min(bytes.len()),
                None => bytes.len(),
            };
            self.encoded.extend_from_slice(&bytes[..accepted]);
            Ok(accepted)
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                return Err(io::Error::other("controlled flush failure"));
            }
            Ok(())
        }
    }

    let mut writer = ControlledWriter {
        encoded: Vec::new(),
        steps: VecDeque::from([Step::Interrupted, Step::Partial(2), Step::Failure]),
        fail_flush: false,
    };
    let mut buffer = StateBuffer::new(&mut writer);
    buffer.write_all(b"abcdef").expect("buffered input");
    assert_eq!(buffer.flush().unwrap_err().kind(), io::ErrorKind::Other);
    assert_eq!(buffer.inner.encoded, b"ab");
    assert_eq!(&buffer.bytes[..buffer.buffered], b"cdef");
    buffer.flush().expect("only unwritten suffix is retried");
    assert_eq!(buffer.inner.encoded, b"abcdef");
    assert_eq!(buffer.buffered, 0);

    buffer.inner.steps.push_back(Step::Zero);
    buffer.write_all(b"tail").expect("final buffered tail");
    assert_eq!(buffer.flush().unwrap_err().kind(), io::ErrorKind::WriteZero);
    assert_eq!(&buffer.bytes[..buffer.buffered], b"tail");
    buffer.flush().expect("tail remains available after error");
    assert_eq!(buffer.inner.encoded, b"abcdeftail");

    buffer.inner.fail_flush = true;
    assert_eq!(buffer.flush().unwrap_err().kind(), io::ErrorKind::Other);
    buffer.inner.fail_flush = false;
    buffer.flush().expect("inner flush errors are propagated");
}

#[test]
fn config_capacity_957_streamed_ledger_buffer_preserves_size_and_output_checks() {
    let key = AuditKey::new([0xC3; 32]).expect("synthetic authentication key");
    let stored = StoredLedger {
        identity: identity(),
        ledger: None,
    };
    let length = canonical_state_len(&stored).expect("original canonical length");
    assert!(length > 1 && length < STATE_STREAM_BUFFER_BYTES);
    for invalid_length in [0, length - 1, length + 1, MAX_STATE_BYTES + 1] {
        assert_eq!(
            stream_state(&stored, &key, invalid_length, None)
                .err()
                .expect("incorrect length must not produce a MAC")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    let mut absent_output = Vec::new();
    assert!(stream_state(&stored, &key, length, Some(&mut absent_output)).is_err());
    assert!(absent_output.is_empty() && absent_output.capacity() == 0);
    let mut occupied_output = vec![0xA5; length];
    let original_capacity = occupied_output.capacity();
    occupied_output.resize(original_capacity, 0xA5);
    assert!(stream_state(&stored, &key, length, Some(&mut occupied_output)).is_err());
    assert_eq!(occupied_output.capacity(), original_capacity);
    assert!(occupied_output.iter().all(|byte| *byte == 0xA5));

    let original_mac = authenticate(&key, STATE_DOMAIN, &stored).expect("original authenticator");
    stream_state(&stored, &key, length, None)
        .expect("exact length flushes the final tail")
        .verify_slice(&original_mac)
        .expect("unchanged final-tail authentication");
    let mut changed = stored;
    changed.identity = ConfigConsensusIdentity::new(
        crate::ConfigConsensusClusterId::from_bytes([0xC6; 32]),
        changed.identity.configuration_id(),
        changed.identity.configuration_epoch(),
    );
    let changed_length = canonical_state_len(&changed).expect("changed canonical value");
    assert!(stream_state(&changed, &key, changed_length, None)
        .expect("changed bytes remain serializable")
        .verify_slice(&original_mac)
        .is_err());
}

#[test]
fn config_capacity_957_streamed_ledger_batches_authenticated_sink_writes() {
    use std::io::Write;

    let (key, mut stored) = super::config_capacity_957_ledger_allocations::fixture(1_023, true);
    for rows in [3_070, 3_071] {
        if rows == 3_071 {
            let ledger = stored.ledger.as_mut().unwrap();
            let selected = ledger.operations.last().unwrap().handle.clone();
            ledger
                .resolve(
                    &key,
                    &selected,
                    AuditOperationState::Committed { version: 2 },
                )
                .expect("same real final outcome transition as the phase diagnostic");
        }
        let ledger = stored.ledger.as_ref().unwrap();
        assert_eq!(ledger.entries.len(), rows);
        assert_eq!(ledger.operations.len(), 1_024);
        ledger
            .validate(&key, stored.identity)
            .expect("valid history");
        let original = serde_json::to_vec(&stored).expect("original canonical bytes");
        let original_mac = authenticate(&key, STATE_DOMAIN, &stored).expect("original MAC");
        let length = canonical_state_len(&stored).expect("actual canonical length");
        assert_eq!(length, original.len());
        let ((output, batched_mac), encoded) = observe_state_stream(|| {
            encode_state(&stored, &key).expect("complete production encoder")
        });
        assert!(
            output == original,
            "batching preserves every canonical byte"
        );
        assert!(batched_mac == original_mac, "batching preserves the MAC");
        let ((), verified) = observe_state_stream(|| {
            stream_state(&stored, &key, length, None)
                .expect("complete production verification stream")
                .verify_slice(&original_mac)
                .expect("original MAC verifies without output allocation");
        });
        let mut original_fragments = FragmentCounts::default();
        serde_json::to_writer(&mut original_fragments, &stored)
            .expect("unbuffered fragment oracle");
        assert_eq!(original_fragments.bytes, length);
        assert_eq!(encoded.fragments.bytes, length);
        assert_eq!(verified.fragments.bytes, length);
        assert_eq!(encoded.output_writes, encoded.fragments.writes);
        assert_eq!(encoded.verification_writes, 0);
        assert_eq!(verified.verification_writes, verified.fragments.writes);
        assert_eq!(verified.output_writes, 0);
        assert_eq!(
            encoded.fragments.writes,
            length.div_ceil(STATE_STREAM_BUFFER_BYTES),
            "CONFIG_CAPACITY_LEDGER_BATCHING_RED: production encoder must batch authenticated sink writes"
        );
        assert_eq!(
            verified.fragments.writes,
            length.div_ceil(STATE_STREAM_BUFFER_BYTES),
            "CONFIG_CAPACITY_LEDGER_BATCHING_RED: production verification must batch authenticated sink writes"
        );
        for observed in [encoded, verified] {
            assert_eq!(observed.fragments.maximum_write, STATE_STREAM_BUFFER_BYTES);
            assert_eq!(
                observed.last_write,
                (length - 1) % STATE_STREAM_BUFFER_BYTES + 1
            );
            assert!(original_fragments.writes > 1_000 * observed.fragments.writes);
        }
        writeln!(
            std::io::stdout().lock(),
            "CONFIG_CAPACITY_LEDGER_BATCHING {}",
            serde_json::json!({
                "rows": rows,
                "operations": 1_024,
                "canonical_bytes": length,
                "serde_writes": original_fragments.writes,
                "authenticated_sink_writes": encoded.fragments.writes,
                "verification_sink_writes": verified.fragments.writes,
                "maximum_sink_write_bytes": encoded.fragments.maximum_write,
                "last_sink_write_bytes": encoded.last_write,
                "stack_buffer_payload_bytes": STATE_STREAM_BUFFER_BYTES,
                "stack_buffer_type_bytes": std::mem::size_of::<StateBuffer<'_, StateByteCounter>>(),
                "original_bytes_and_mac_equal": true,
                "production_bytes_and_mac_equal": true,
                "test_cfg_sink_observer": true,
                "whole_operation_memory_bound": false,
                "timing_qualification": false,
                "native_rpc_qualification": false
            })
        )
        .unwrap();
    }
}
