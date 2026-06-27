mod lifecycle_common;

use lifecycle_common::*;
use operator_lifecycle::sanitize_denial_message;

#[test]
fn test_denial_messages_are_redacted() {
    // 1. Path redaction
    let msg1 = "Failed to load cert from /etc/secrets/admin.pem due to permission error";
    let res1 = sanitize_denial_message(msg1);
    assert_eq!(
        res1,
        "Failed to load cert from [REDACTED_PATH] due to permission error"
    );

    // 2. IP address redaction
    let msg2 = "Peer 192.0.2.10:4500 failed NAT-T keepalive";
    let res2 = sanitize_denial_message(msg2);
    assert_eq!(
        res2,
        "Peer [REDACTED_IPV4]:[REDACTED_PORT] failed NAT-T keepalive"
    );

    // 3. Subscriber ID redaction
    let msg3 = "Subscriber 208950000000001 session establishment failed";
    let res3 = sanitize_denial_message(msg3);
    assert_eq!(
        res3,
        "Subscriber [REDACTED_SUBSCRIBER_ID] session establishment failed"
    );

    let msg3b = "Subscriber imsi=208950000000001 session establishment failed";
    let res3b = sanitize_denial_message(msg3b);
    assert_eq!(
        res3b,
        "Subscriber imsi=[REDACTED_SUBSCRIBER_ID] session establishment failed"
    );

    // 4. PEM block redaction
    let msg4 = "Invalid certificate format: -----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END CERTIFICATE-----";
    let res4 = sanitize_denial_message(msg4);
    assert_eq!(res4, "[REDACTED_PEM_CERT_MATERIAL]");

    // 5. SQL query redaction
    let msg5 = "Database transaction failed on SELECT * FROM session_store WHERE supi = 12345";
    let res5 = sanitize_denial_message(msg5);
    assert_eq!(res5, "[REDACTED_SQL_OR_DB_ERROR]");

    // 6. Safe lifecycle prose remains unchanged.
    let msg6 = "workload is starting up";
    let res6 = sanitize_denial_message(msg6);
    assert_eq!(res6, "workload is starting up");
}

#[test]
fn test_lifecycle_condition_messages_are_sanitized() {
    let now = OffsetDateTime::now_utc();
    let mut status = LifecycleStatus::new(1);

    status.set_condition(
        "Ready",
        ConditionStatus::False,
        "SecretLeak",
        "peer 192.0.2.10 failed for subscriber 208950000000001 using /etc/secrets/admin.pem",
        1,
        ConditionSeverity::Error,
        false,
        now,
    );

    let cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(
        cond.message,
        "peer [REDACTED_IPV4] failed for subscriber [REDACTED_SUBSCRIBER_ID] using [REDACTED_PATH]"
    );
    assert!(cond.redaction_safe_text);
}

#[test]
fn test_compatibility_sanitized_messages() {
    let raw_msg =
        "admission failed for subscriber 208950000000001 and path /var/run/secrets/config";
    let sanitized = sanitize_denial_message(raw_msg);
    assert!(!sanitized.contains("208950000000001"));
    assert!(!sanitized.contains("/var/run/secrets/config"));
    assert!(sanitized.contains("[REDACTED_SUBSCRIBER_ID]"));
    assert!(sanitized.contains("[REDACTED_PATH]"));
}

#[test]
fn test_lifecycle_condition_preserves_sdk_redaction_placeholders() {
    let now = OffsetDateTime::now_utc();
    let mut status = LifecycleStatus::new(1);

    status.set_condition(
        "Ready",
        ConditionStatus::False,
        "AlreadyRedacted",
        "peer [REDACTED_IPV4] used [REDACTED_PATH] for [REDACTED_SUBSCRIBER_ID]",
        1,
        ConditionSeverity::Warning,
        true,
        now,
    );

    let cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(
        cond.message,
        "peer [REDACTED_IPV4] used [REDACTED_PATH] for [REDACTED_SUBSCRIBER_ID]"
    );
    assert!(cond.redaction_safe_text);
}
