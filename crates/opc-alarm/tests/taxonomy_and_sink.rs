use async_trait::async_trait;
use opc_alarm::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;

#[test]
fn test_taxonomy_version_stability() {
    assert_eq!(TAXONOMY_VERSION, "1.0.0");
}

#[test]
fn test_severity_serialization_compatibility() {
    let cases = vec![
        (Severity::Cleared, "cleared"),
        (Severity::Indeterminate, "indeterminate"),
        (Severity::Warning, "warning"),
        (Severity::Minor, "minor"),
        (Severity::Major, "major"),
        (Severity::Critical, "critical"),
    ];

    for (severity, expected_json) in cases {
        let json_str = serde_json::to_string(&severity).unwrap();
        assert_eq!(json_str, format!("\"{expected_json}\""));

        let deserialized: Severity = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized, severity);
    }
}

#[test]
fn test_probable_cause_serialization_compatibility() {
    let cases = vec![
        (ProbableCause::ConfigApplyFailed, "config-apply-failed"),
        (ProbableCause::ConfigDriftDetected, "config-drift-detected"),
        (ProbableCause::CertificateExpiring, "certificate-expiring"),
        (ProbableCause::CertificateExpired, "certificate-expired"),
        (ProbableCause::IdentityUnavailable, "identity-unavailable"),
        (
            ProbableCause::AuthorizationPolicyInvalid,
            "authorization-policy-invalid",
        ),
        (
            ProbableCause::SessionStoreUnavailable,
            "session-store-unavailable",
        ),
        (ProbableCause::LeaseLost, "lease-lost"),
        (ProbableCause::BackendTimeout, "backend-timeout"),
        (ProbableCause::NrfUnreachable, "nrf-unreachable"),
        (ProbableCause::SbiOverload, "sbi-overload"),
        (ProbableCause::PeerUnreachable, "peer-unreachable"),
        (ProbableCause::PacketDropThreshold, "packet-drop-threshold"),
        (
            ProbableCause::DataplanePreflightFailed,
            "dataplane-preflight-failed",
        ),
        (ProbableCause::StorageCorruption, "storage-corruption"),
        (ProbableCause::AuditChainInvalid, "audit-chain-invalid"),
        (ProbableCause::KeyUnavailable, "key-unavailable"),
        (ProbableCause::LiDeliveryFailed, "li-delivery-failed"),
        (
            ProbableCause::ChargingExportFailed,
            "charging-export-failed",
        ),
        (
            ProbableCause::PrivacyPolicyViolation,
            "privacy-policy-violation",
        ),
        (ProbableCause::SecurityBreakGlass, "security-break-glass"),
        (
            ProbableCause::Other("upf.gtp.PortExhaustion".to_string()),
            "other:upf.gtp.PortExhaustion",
        ),
    ];

    for (cause, expected_json) in cases {
        let json_str = serde_json::to_string(&cause).unwrap();
        assert_eq!(json_str, format!("\"{expected_json}\""));

        let deserialized: ProbableCause = serde_json::from_str(&json_str).unwrap();
        assert_eq!(deserialized, cause);
    }
}

fn make_dummy_alarm() -> Alarm {
    Alarm {
        alarm_id: AlarmId::new("test-alarm-id"),
        alarm_type: AlarmType::new("test-type"),
        severity: Severity::Major,
        probable_cause: ProbableCause::PeerUnreachable,
        affected_object: AffectedObject::NfInstance {
            kind: "upf".to_string(),
            instance: "upf-1".to_string(),
        },
        tenant: None,
        slice: None,
        region: None,
        text: RedactedText::new("test text"),
        details: AlarmDetails::empty(),
        state: AlarmState::Raised,
        raised_at: OffsetDateTime::now_utc(),
        updated_at: OffsetDateTime::now_utc(),
        cleared_at: None,
        correlation_id: None,
    }
}

#[test]
fn exported_alarm_snapshot_redacts_text_and_details() {
    let mut alarm = make_dummy_alarm();
    alarm.text = RedactedText::new("peer 10.0.0.1 imsi 208950000000001 down");
    alarm.details = AlarmDetails::with_value(serde_json::json!({
        "description": "subscriber imsi 208950000000001 on 10.0.0.1"
    }));

    let exported = alarm.redacted_for_export();
    let serialized = serde_json::to_string(&exported).unwrap();

    assert!(!serialized.contains("208950000000001"));
    assert!(!serialized.contains("10.0.0.1"));
}

#[tokio::test]
async fn test_recording_and_tracing_sinks() {
    let rec_sink = RecordingSink::new();
    let alarm = make_dummy_alarm();
    rec_sink.send(alarm.clone()).await.unwrap();
    assert_eq!(rec_sink.get_alarms().len(), 1);
    assert_eq!(rec_sink.get_alarms()[0].alarm_id, alarm.alarm_id);

    let tracing_sink = TracingSink::new();
    tracing_sink.send(alarm).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn test_bounded_alarm_sink_queue_full() {
    // To reliably fill a queue of capacity 1, we can wrap a blocking/stub sink.

    struct SlowSink {
        barrier: Arc<tokio::sync::Barrier>,
    }
    #[async_trait]
    impl AlarmSink for SlowSink {
        async fn send(&self, _alarm: Alarm) -> Result<(), AlarmSinkError> {
            self.barrier.wait().await;
            Ok(())
        }
    }

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let slow = SlowSink {
        barrier: Arc::clone(&barrier),
    };
    // Bounded queue size = 1
    let bounded_slow = BoundedAlarmSink::new(slow, 1, 0, Duration::from_millis(1));

    // Send 1: worker pulls it from queue immediately and blocks on the barrier
    bounded_slow.send(make_dummy_alarm()).await.unwrap();

    // Sleep to let the worker run and pull the item from the queue
    tokio::time::sleep(Duration::from_millis(5)).await;

    // Send 2: fills the queue capacity of 1
    bounded_slow.send(make_dummy_alarm()).await.unwrap();

    // Send 3: queue is full, try_send returns QueueFull
    let err = bounded_slow.send(make_dummy_alarm()).await.unwrap_err();
    assert_eq!(err, AlarmSinkError::QueueFull);

    // Release the worker
    barrier.wait().await;
}

#[tokio::test(start_paused = true)]
async fn test_bounded_alarm_sink_retry_exhaustion() {
    struct FailingSink {
        calls: Arc<Mutex<usize>>,
    }
    #[async_trait]
    impl AlarmSink for FailingSink {
        async fn send(&self, _alarm: Alarm) -> Result<(), AlarmSinkError> {
            let mut guard = self.calls.lock().unwrap();
            *guard += 1;
            Err(AlarmSinkError::DeliveryFailed("mock failure".to_string()))
        }
    }

    let calls = Arc::new(Mutex::new(0));
    let failing = FailingSink {
        calls: Arc::clone(&calls),
    };

    // Bounded sink with max_retries = 2 (total 3 attempts)
    let bounded = BoundedAlarmSink::new(failing, 10, 2, Duration::from_millis(5));

    bounded.send(make_dummy_alarm()).await.unwrap();

    // Wait for worker to exhaust retries
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(bounded.status(), SinkStatus::Ok);
    assert_eq!(bounded.dropped_count(), 1);
    assert!(bounded.last_error().unwrap().contains("mock failure"));

    // Subsequent sends are accepted; each poisoned alarm is counted and dropped
    // independently without stopping the worker.
    bounded.send(make_dummy_alarm()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(bounded.status(), SinkStatus::Ok);
    assert_eq!(bounded.dropped_count(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_bounded_alarm_sink_drops_poisoned_alarm_and_recovers() {
    struct FlakySink {
        remaining_failures: Arc<Mutex<usize>>,
        delivered: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl AlarmSink for FlakySink {
        async fn send(&self, alarm: Alarm) -> Result<(), AlarmSinkError> {
            let mut remaining = self.remaining_failures.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                return Err(AlarmSinkError::DeliveryFailed(
                    "temporary outage".to_string(),
                ));
            }
            self.delivered
                .lock()
                .unwrap()
                .push(alarm.alarm_id.as_str().to_string());
            Ok(())
        }
    }

    let delivered = Arc::new(Mutex::new(Vec::new()));
    let sink = FlakySink {
        remaining_failures: Arc::new(Mutex::new(1)),
        delivered: Arc::clone(&delivered),
    };
    let bounded = BoundedAlarmSink::new(sink, 10, 0, Duration::from_millis(1));
    let mut poisoned = make_dummy_alarm();
    poisoned.alarm_id = AlarmId::new("poisoned");
    let mut recovered = make_dummy_alarm();
    recovered.alarm_id = AlarmId::new("recovered");

    bounded.send(poisoned).await.unwrap();
    bounded.send(recovered).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;

    assert_eq!(bounded.status(), SinkStatus::Ok);
    assert_eq!(bounded.dropped_count(), 1);
    assert_eq!(*delivered.lock().unwrap(), vec!["recovered".to_string()]);
}

#[tokio::test(start_paused = true)]
async fn test_bounded_alarm_sink_redacts_retry_error() {
    struct SensitiveFailingSink;
    #[async_trait]
    impl AlarmSink for SensitiveFailingSink {
        async fn send(&self, _alarm: Alarm) -> Result<(), AlarmSinkError> {
            Err(AlarmSinkError::DeliveryFailed(
                "sqlite database /Users/alice/private.db failed for imsi-208950000000001"
                    .to_string(),
            ))
        }
    }

    let bounded = BoundedAlarmSink::new(SensitiveFailingSink, 1, 0, Duration::from_millis(1));
    bounded.send(make_dummy_alarm()).await.unwrap();

    tokio::time::sleep(Duration::from_millis(25)).await;

    let last_error = bounded.last_error().unwrap_or_default();
    assert!(last_error.contains("REDACTED") || last_error.contains("<redacted>"));
    assert!(!last_error.contains("/Users/alice"));
    assert!(!last_error.contains("208950000000001"));

    bounded.send(make_dummy_alarm()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;
    let last_error = bounded.last_error().unwrap_or_default();
    assert!(!last_error.contains("/Users/alice"));
    assert!(!last_error.contains("208950000000001"));
    assert_eq!(bounded.dropped_count(), 2);
}

#[tokio::test(start_paused = true)]
async fn test_bounded_alarm_sink_zero_capacity_is_safe() {
    let rec_sink = RecordingSink::new();
    let rec_view = rec_sink.clone();
    let bounded = BoundedAlarmSink::new(rec_sink, 0, 0, Duration::from_millis(1));

    bounded.send(make_dummy_alarm()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(25)).await;

    assert_eq!(rec_view.get_alarms().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn test_bounded_alarm_sink_shutdown() {
    let rec_sink = RecordingSink::new();
    let rec_view = rec_sink.clone();
    let bounded = BoundedAlarmSink::new(rec_sink, 10, 0, Duration::from_millis(1));

    bounded.send(make_dummy_alarm()).await.unwrap();
    bounded.shutdown();
    assert_eq!(bounded.status(), SinkStatus::Shutdown);

    let err = bounded.send(make_dummy_alarm()).await.unwrap_err();
    assert_eq!(err, AlarmSinkError::Shutdown);

    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(rec_view.get_alarms().len(), 1);
}

#[test]
fn test_bounded_alarm_sink_constructor_outside_tokio_runtime_is_safe() {
    let bounded = BoundedAlarmSink::new(RecordingSink::new(), 1, 0, Duration::from_millis(1));
    bounded.shutdown();
    assert_eq!(bounded.status(), SinkStatus::Shutdown);
}
