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
        "Failed to load cert from [redacted-path] due to permission error"
    );

    // 2. Token redaction
    let msg2 = "Access denied with token abcdefabcdef1234567890123456";
    let res2 = sanitize_denial_message(msg2);
    assert_eq!(res2, "Access denied with token [redacted-token]");

    let msg2b = "Production specification uses an insecure/unsafe admin token: admin123";
    let res2b = sanitize_denial_message(msg2b);
    assert_eq!(
        res2b,
        "Production specification uses an insecure/unsafe admin token: [redacted-token]"
    );

    let msg2c = "Access denied with admin_token=admin123";
    let res2c = sanitize_denial_message(msg2c);
    assert_eq!(res2c, "Access denied with [redacted-token]");

    // 3. Subscriber ID redaction
    let msg3 = "Subscriber 208950000000001 session establishment failed";
    let res3 = sanitize_denial_message(msg3);
    assert_eq!(
        res3,
        "Subscriber [redacted-subscriber-id] session establishment failed"
    );

    let msg3b = "Subscriber imsi=208950000000001 session establishment failed";
    let res3b = sanitize_denial_message(msg3b);
    assert_eq!(
        res3b,
        "Subscriber [redacted-subscriber-id] session establishment failed"
    );

    // 4. PEM block redaction
    let msg4 = "Invalid certificate format: -----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END CERTIFICATE-----";
    let res4 = sanitize_denial_message(msg4);
    assert_eq!(res4, "[redacted-pem]");

    // 5. SQL query redaction
    let msg5 = "Database transaction failed on SELECT * FROM session_store WHERE supi = 12345";
    let res5 = sanitize_denial_message(msg5);
    assert_eq!(res5, "[redacted-sql]");

    // 6. Config blob redaction
    let msg6 = "Failed to apply JSON configuration payload: {\"host\":\"localhost\",\"port\":80}";
    let res6 = sanitize_denial_message(msg6);
    assert_eq!(res6, "[redacted-config]");
}

#[test]
fn test_lifecycle_condition_messages_are_sanitized() {
    let now = OffsetDateTime::now_utc();
    let mut status = LifecycleStatus::new(1);

    status.set_condition(
        "Ready",
        ConditionStatus::False,
        "SecretLeak",
        "failed with token admin123 from /etc/secrets/admin.pem",
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
        "failed with token [redacted-token] from [redacted-path]"
    );
    assert!(cond.redaction_safe_text);
}

#[test]
fn test_compatibility_sanitized_messages() {
    let raw_msg = "admission failed with token admin123 and path /var/run/secrets/config";
    let sanitized = sanitize_denial_message(raw_msg);
    assert!(!sanitized.contains("admin123"));
    assert!(!sanitized.contains("/var/run/secrets/config"));
    assert!(sanitized.contains("[redacted-token]"));
    assert!(sanitized.contains("[redacted-path]"));
}
