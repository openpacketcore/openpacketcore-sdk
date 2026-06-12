mod evidence_common;
use evidence_common::*;

#[test]
fn test_gap_006_005_performance_baseline() {
    assert_eq!(
        evaluate_threshold(100.0, 150.0, true),
        RegressionStatus::Pass
    );
    assert_eq!(
        evaluate_threshold(200.0, 150.0, true),
        RegressionStatus::Regression
    );
    assert_eq!(
        evaluate_threshold(100.0, 50.0, false),
        RegressionStatus::Pass
    );
    assert_eq!(
        evaluate_threshold(40.0, 50.0, false),
        RegressionStatus::Regression
    );

    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/dummy".to_string());
    let raw_cmd =
        format!("cargo run --release --config {home}/secret_config.json --ip 192.168.1.50");
    let redacted = redact_secrets_and_paths(&raw_cmd);

    assert!(redacted.contains("<home>"));
    assert!(!redacted.contains(&home));
    assert!(redacted.contains("<ip-redacted>"));
    assert!(!redacted.contains("192.168.1.50"));

    let baseline = PerformanceBaseline {
        schema_version: "1.0.0".to_string(),
        generated_at: "2026-06-08T12:00:00Z".to_string(),
        benchmark: "test-bench".to_string(),
        metrics: vec![PerformanceMetric {
            name: "latency".to_string(),
            unit: "ms".to_string(),
            value: 12.5,
        }],
        environment: Some(EnvironmentMetadata {
            os: "macos".to_string(),
            arch: "aarch64".to_string(),
            rust_version: Some("1.81.0".to_string()),
            cpu_summary: Some("Apple M3".to_string()),
            test_profile: "release".to_string(),
            command: "cargo test".to_string(),
            timestamp: "2026-06-08T12:00:00Z".to_string(),
        }),
        regression_status: Some(RegressionStatus::Pass),
    };

    let serialized = serde_json::to_string(&baseline).unwrap();
    assert!(serialized.contains("environment"));
    assert!(serialized.contains("regression_status"));
    assert!(serialized.contains("cargo test"));
    assert!(serialized.contains("\"schema_version\":\"1.0.0\""));
    assert!(serialized.contains("\"benchmark\":\"test-bench\""));
}
