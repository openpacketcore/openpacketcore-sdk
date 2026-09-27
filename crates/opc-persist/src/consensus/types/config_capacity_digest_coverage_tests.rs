//! Compatibility and I/O fault controls for the paired transcript boundary.
//! These component fixtures do not grant admission or retained-history authority.

use super::*;
use crate::audit_authority::ledger::HandleBody;
use crate::audit_authority::{
    AuditCaller, AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey, AuditToken,
    ProjectedAuditEvent,
};
use crate::consensus::audit_mutation::{AuditedConfigEffect, PreparedAuditedMutation};
use crate::consensus::history::{ConfigHistoryLimits, ConfigHistoryRetention};
use std::io::{self, Write};

fn command_with(intent: ConfigMutationIntent) -> ConfigConsensusCommand {
    ConfigConsensusCommand {
        // The expected semantic revisions in the tests are selected separately.
        schema_version: 7,
        identity: identity(),
        request_id: ConfigConsensusRequestId::from_bytes([0xC0; 16]),
        logical_time: Timestamp::from_str("2026-01-01T00:00:00Z").expect("synthetic time"),
        intent,
    }
}

fn legacy_audited_intent(effect: AuditedConfigEffect) -> ConfigMutationIntent {
    let key = AuditKey::new([0xC1; 32]).expect("synthetic audit key");
    let privacy = AuditPrivacyKey::new([0xC2; 32]).expect("synthetic projection key");
    let caller = AuditCaller::project(&privacy, "test", "synthetic-digest-coverage")
        .expect("synthetic caller projection");
    let token = AuditToken::from_keyed_projection([0xC3; 32]).expect("synthetic token");
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding: AuditOperationBinding {
                caller,
                request: token,
                operation: token,
                base_version: 1,
            },
            event: ProjectedAuditEvent {
                projection: token,
                caller,
                request: token,
                transaction: None,
                paths: token,
                reason: None,
                transport: crate::ManagementAuditTransportCode::Gnmi,
                operation: crate::ManagementAuditOperationCode::Update,
                outcome: crate::ManagementAuditOutcomeCode::Intent,
                utc_seconds: 100,
                nanosecond: 0,
            },
            issued_at: 100,
            expires_at: 160,
            nonce: [0xC4; 16],
            key_epoch: key.epoch(),
            mutation: Some(effect.digest(&key).expect("original effect HMAC")),
        },
        &key,
    )
    .expect("synthetic authenticated handle bytes");
    ConfigMutationIntent::AuditedMutation(
        PreparedAuditedMutation::new(handle, effect, None)
            .command()
            .clone(),
    )
}

#[test]
fn config_capacity_joint_digests_cover_resolution_retention_and_legacy_audited_families() {
    let tx_id = TxId::from_uuid(uuid::Uuid::from_u128(0xC5));
    let ConfigMutationIntent::AppendCommit(ordinary) =
        fixture(ConfigCapacityProfile::Legacy).command.intent
    else {
        unreachable!("legacy append fixture")
    };
    let ConfigMutationIntent::AppendCommit(successor) =
        fixture_with_parent(ConfigCapacityProfile::Legacy, Some(tx_id))
            .command
            .intent
    else {
        unreachable!("legacy successor fixture")
    };
    let confirm = ConfirmedCommitResolution::Confirm {
        pending_tx_id: tx_id,
    };
    let rollback = ConfirmedCommitResolution::Rollback {
        pending_tx_id: tx_id,
    };
    let label = ValidatedRollbackLabel::try_new("coverage-λ-\\\"".to_owned())
        .expect("escaped rollback label");
    let retention = ConfigHistoryRetention::new(
        tx_id,
        ConfigVersion::new(4),
        ConfigVersion::new(2),
        ConfigVersion::new(3),
        ConfigHistoryLimits::new(2, 65_536).expect("synthetic history limits"),
    )
    .expect("synthetic exact-head retention fields");
    let mut cases = vec![
        (
            "resolve-confirm",
            2_u16,
            ConfigMutationIntent::ResolveConfirmedAndAppend {
                commit: successor.clone(),
                resolution: confirm,
            },
        ),
        (
            "resolve-rollback",
            2,
            ConfigMutationIntent::ResolveConfirmedAndAppend {
                commit: successor.clone(),
                resolution: rollback,
            },
        ),
        (
            "clear",
            2,
            ConfigMutationIntent::ClearRecoveryRequired { tx_id },
        ),
        (
            "rollback-none",
            1,
            ConfigMutationIntent::CreateRollbackPoint { tx_id, label: None },
        ),
        (
            "rollback-label",
            1,
            ConfigMutationIntent::CreateRollbackPoint {
                tx_id,
                label: Some(label.clone()),
            },
        ),
        (
            "retention",
            4,
            ConfigMutationIntent::RetainHistory(retention),
        ),
    ];
    for (name, effect) in [
        (
            "audited-append",
            AuditedConfigEffect::Append {
                commit: ordinary,
                resolution: None,
            },
        ),
        (
            "audited-resolve-confirm",
            AuditedConfigEffect::Append {
                commit: successor.clone(),
                resolution: Some(confirm),
            },
        ),
        (
            "audited-resolve-rollback",
            AuditedConfigEffect::Append {
                commit: successor,
                resolution: Some(rollback),
            },
        ),
        ("audited-confirm", AuditedConfigEffect::Confirm { tx_id }),
        (
            "audited-rollback-none",
            AuditedConfigEffect::RollbackPoint { tx_id, label: None },
        ),
        (
            "audited-rollback-label",
            AuditedConfigEffect::RollbackPoint {
                tx_id,
                label: Some(label),
            },
        ),
    ] {
        cases.push((name, 5, legacy_audited_intent(effect)));
    }
    for (name, revision, intent) in cases {
        let command = command_with(intent);
        // This checks both original calculators, both complete paired streams,
        // and both paired hashes against Serde and literal-domain oracles.
        require_original_transcripts(&command, revision);
        println!("CONFIG_CAPACITY_JOINT_FAMILY family={name} revision={revision} bytes_and_both_calculators_equal=true");
    }
}

#[test]
fn config_capacity_joint_digests_cover_timestamp_and_sequence_boundaries() {
    let cases = [
        ("0000-01-01T00:00:00Z", "0000-01-01T00:00:00Z"),
        (
            "9999-12-31T23:59:59.999999999Z",
            "9999-12-31T23:59:59.999999999Z",
        ),
        ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        (
            "2026-01-01T00:00:00.000000001Z",
            "2026-01-01T00:00:00.000000001Z",
        ),
        ("2026-01-01T00:00:00.100000000Z", "2026-01-01T00:00:00.1Z"),
        (
            "2026-01-01T05:30:00.123456789+05:30",
            "2026-01-01T00:00:00.123456789Z",
        ),
        ("2025-12-31T20:00:00.1-04:00", "2026-01-01T00:00:00.1Z"),
    ];
    let times: Vec<_> = cases
        .into_iter()
        .map(|(input, normalized)| {
            let parsed = Timestamp::from_str(input).expect("representable boundary timestamp");
            assert_eq!(
                serde_json::to_vec(&parsed).expect("original timestamp serializer"),
                serde_json::to_vec(normalized).expect("literal normalized timestamp")
            );
            parsed
        })
        .collect();
    let previous = ConfigConsensusEntryDigest::from_bytes([0xC6; 32]);
    let mut command = command_with(ConfigMutationIntent::MarkConfirmed {
        tx_id: TxId::from_uuid(uuid::Uuid::from_u128(0xC7)),
    });
    // Sequence zero and u64::MAX are encoding controls, not apply authorization.
    for logical_time in &times {
        command.logical_time = *logical_time;
        for effective_time in &times {
            for sequence in [0, 1, i64::MAX as u64, u64::MAX - 1, u64::MAX] {
                require_original_transcripts_at(&command, 1, sequence, previous, *effective_time);
            }
        }
    }
}

#[test]
fn config_capacity_joint_digests_reject_unrepresentable_timestamp_fields() {
    let invalid = Timestamp::from_offset_datetime(
        time::Date::from_calendar_date(-1, time::Month::January, 1)
            .expect("representable time-library date outside RFC 3339")
            .midnight()
            .assume_utc(),
    );
    assert!(
        serde_json::to_vec(&invalid).is_err(),
        "independent timestamp serialization error"
    );
    let previous = ConfigConsensusEntryDigest::from_bytes([0xC8; 32]);
    for field in ["logical", "effective", "intent"] {
        let mut command = command_with(ConfigMutationIntent::MarkConfirmed {
            tx_id: TxId::from_uuid(uuid::Uuid::from_u128(0xC9)),
        });
        let mut effective_time = command.logical_time;
        match field {
            "logical" => command.logical_time = invalid,
            "effective" => effective_time = invalid,
            "intent" => {
                command.intent = fixture(ConfigCapacityProfile::Legacy).command.intent;
                let ConfigMutationIntent::AppendCommit(commit) = &mut command.intent else {
                    unreachable!("legacy append fixture")
                };
                commit.record.committed_at = invalid;
            }
            _ => unreachable!("closed field cases"),
        }
        let original_outcome = serde_json::to_vec(&(1_u16, command.identity, &command.intent));
        assert_eq!(original_outcome.is_err(), field == "intent");
        assert_eq!(command.payload_digest().is_err(), original_outcome.is_err());
        assert!(serde_json::to_vec(&(1_u64, previous, effective_time, &command)).is_err());
        assert!(command
            .calculate_applied_digest(1, previous, effective_time)
            .is_err());
        assert!(command
            .payload_and_applied_digests(1, previous, effective_time)
            .is_err());
        let mut outcome = Vec::new();
        let mut applied = Vec::new();
        assert!(
            config_capacity_joint_digest::write_transcripts(
                &command,
                1,
                previous,
                effective_time,
                &mut outcome,
                &mut applied,
            )
            .is_err(),
            "partial streams must never be returned as a successful transcript pair"
        );
    }
}

#[derive(Clone, Copy)]
enum WriteFault {
    Interrupted,
    Zero,
    Error,
}

struct FaultSink {
    bytes: Vec<u8>,
    max_write: usize,
    write_fault: Option<(usize, WriteFault)>,
    write_fault_hits: usize,
    flush_fault: Option<io::ErrorKind>,
    flush_calls: usize,
}

impl FaultSink {
    fn new(max_write: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_write,
            write_fault: None,
            write_fault_hits: 0,
            flush_fault: None,
            flush_calls: 0,
        }
    }
}

impl Write for FaultSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut count = bytes.len().min(self.max_write);
        if let Some((at, fault)) = self.write_fault {
            if self.bytes.len() >= at {
                self.write_fault_hits += 1;
                return match fault {
                    WriteFault::Interrupted => {
                        self.write_fault = None;
                        Err(io::Error::from(io::ErrorKind::Interrupted))
                    }
                    WriteFault::Zero => Ok(0),
                    WriteFault::Error => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "synthetic transcript write fault",
                    )),
                };
            }
            count = count.min(at - self.bytes.len());
        }
        self.bytes.extend_from_slice(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_calls += 1;
        match self.flush_fault {
            Some(kind) => Err(io::Error::new(kind, "synthetic transcript flush fault")),
            None => Ok(()),
        }
    }
}

struct TranscriptFixture {
    command: ConfigConsensusCommand,
    sequence: u64,
    previous: ConfigConsensusEntryDigest,
    effective_time: Timestamp,
    outcome: Vec<u8>,
    applied: Vec<u8>,
    outcome_intent: usize,
    applied_intent: usize,
}

impl TranscriptFixture {
    fn new() -> Self {
        let command = command_with(ConfigMutationIntent::CreateRollbackPoint {
            tx_id: TxId::from_uuid(uuid::Uuid::from_u128(0xCA)),
            label: Some(
                ValidatedRollbackLabel::try_new("fault-λ-\\\"".to_owned()).expect("escaped label"),
            ),
        });
        let sequence = u64::MAX;
        let previous = ConfigConsensusEntryDigest::from_bytes([0xCB; 32]);
        let effective_time =
            Timestamp::from_str("2026-01-01T00:00:00.000000001Z").expect("synthetic time");
        let outcome = serde_json::to_vec(&(1_u16, command.identity, &command.intent))
            .expect("independent complete outcome");
        let applied = serde_json::to_vec(&(sequence, previous, effective_time, &command))
            .expect("independent complete applied");
        let intent = serde_json::to_vec(&command.intent).expect("independent common intent");
        // Locate the common body from independent full transcripts and their
        // existing tuple/struct suffixes, not from the paired writer's counters.
        let outcome_intent = outcome.len() - intent.len() - 1;
        let applied_intent = applied.len() - intent.len() - 2;
        assert_eq!(
            &outcome[outcome_intent..outcome.len() - 1],
            intent.as_slice()
        );
        assert_eq!(
            &applied[applied_intent..applied.len() - 2],
            intent.as_slice()
        );
        Self {
            command,
            sequence,
            previous,
            effective_time,
            outcome,
            applied,
            outcome_intent,
            applied_intent,
        }
    }

    fn write(&self, outcome: &mut FaultSink, applied: &mut FaultSink) -> io::Result<()> {
        config_capacity_joint_digest::write_transcripts(
            &self.command,
            self.sequence,
            self.previous,
            self.effective_time,
            outcome,
            applied,
        )
    }
}

#[test]
fn config_capacity_joint_digests_fault_sinks_preserve_complete_short_writes() {
    let fixture = TranscriptFixture::new();
    for (outcome_max, applied_max) in [(1, 3), (7, 1), (4096, 4096)] {
        let mut outcome = FaultSink::new(outcome_max);
        let mut applied = FaultSink::new(applied_max);
        fixture
            .write(&mut outcome, &mut applied)
            .expect("complete streams after short writes");
        assert_eq!(outcome.bytes, fixture.outcome);
        assert_eq!(applied.bytes, fixture.applied);
        assert_eq!((outcome.flush_calls, applied.flush_calls), (1, 1));
    }
}

#[test]
fn config_capacity_joint_digests_fault_sinks_retry_interrupted_in_either_intent_arm() {
    let fixture = TranscriptFixture::new();
    for outcome_arm in [true, false] {
        let mut outcome = FaultSink::new(3);
        let mut applied = FaultSink::new(5);
        if outcome_arm {
            outcome.write_fault = Some((fixture.outcome_intent + 3, WriteFault::Interrupted));
        } else {
            applied.write_fault = Some((fixture.applied_intent + 3, WriteFault::Interrupted));
        }
        fixture
            .write(&mut outcome, &mut applied)
            .expect("interrupted write retried without duplication");
        assert_eq!(outcome.bytes, fixture.outcome);
        assert_eq!(applied.bytes, fixture.applied);
        assert_eq!(
            (outcome.write_fault_hits, applied.write_fault_hits),
            if outcome_arm { (1, 0) } else { (0, 1) }
        );
    }
}

#[test]
fn config_capacity_joint_digests_fault_sinks_reject_writezero_and_write_errors() {
    let fixture = TranscriptFixture::new();
    for fault in [WriteFault::Zero, WriteFault::Error] {
        for outcome_arm in [true, false] {
            let mut outcome = FaultSink::new(3);
            let mut applied = FaultSink::new(5);
            if outcome_arm {
                outcome.write_fault = Some((fixture.outcome_intent + 3, fault));
            } else {
                applied.write_fault = Some((fixture.applied_intent + 3, fault));
            }
            assert!(fixture.write(&mut outcome, &mut applied).is_err());
            assert_eq!(
                (outcome.write_fault_hits, applied.write_fault_hits),
                if outcome_arm { (1, 0) } else { (0, 1) }
            );
            let failed_length = if outcome_arm {
                outcome.bytes.len()
            } else {
                applied.bytes.len()
            };
            let expected_length = if outcome_arm {
                fixture.outcome_intent + 3
            } else {
                fixture.applied_intent + 3
            };
            assert_eq!(
                failed_length, expected_length,
                "fault reached inside the shared intent"
            );
            assert!(fixture.outcome.starts_with(&outcome.bytes));
            assert!(fixture.applied.starts_with(&applied.bytes));
            assert_eq!(
                (outcome.flush_calls, applied.flush_calls),
                (0, 0),
                "failed serialization cannot complete either transcript"
            );
            // Discard both partial streams: the first arm may be ahead of the
            // second, and the JSON wrapper need not preserve the I/O error kind.
        }
    }
}

#[test]
fn config_capacity_joint_digests_fault_sinks_propagate_flush_errors() {
    let fixture = TranscriptFixture::new();
    for kind in [io::ErrorKind::Interrupted, io::ErrorKind::BrokenPipe] {
        for outcome_arm in [true, false] {
            let mut outcome = FaultSink::new(3);
            let mut applied = FaultSink::new(5);
            if outcome_arm {
                outcome.flush_fault = Some(kind);
            } else {
                applied.flush_fault = Some(kind);
            }
            let error = fixture
                .write(&mut outcome, &mut applied)
                .expect_err("flush failure cannot report successful transcripts");
            assert_eq!(error.kind(), kind);
            assert_eq!(outcome.bytes, fixture.outcome);
            assert_eq!(applied.bytes, fixture.applied);
            assert_eq!(
                (outcome.flush_calls, applied.flush_calls),
                if outcome_arm { (1, 0) } else { (1, 1) }
            );
        }
    }
}
