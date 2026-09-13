use super::*;
use std::collections::HashMap;

#[test]
fn canonical_objects_ignore_map_iteration_order_and_encoding_is_bounded() {
    let left = HashMap::from([("a", 1), ("b", 2)]);
    let right = HashMap::from([("b", 2), ("a", 1)]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    assert_eq!(
        canonical_config(&left, 1024, deadline).unwrap(),
        canonical_config(&right, 1024, deadline).unwrap()
    );
    assert_eq!(
        canonical_config(&left, 2, deadline),
        Err(ConfigConsumerError::Limit)
    );
    assert_eq!(
        canonical_config(&left, 1024, tokio::time::Instant::now()),
        Err(ConfigConsumerError::Limit)
    );
}

#[test]
fn status_and_errors_are_value_free() {
    for phase in [
        ConfigConsumerPhase::Unobserved,
        ConfigConsumerPhase::Observed,
        ConfigConsumerPhase::ApplyPending,
        ConfigConsumerPhase::ReadbackRequired,
        ConfigConsumerPhase::Applied,
    ] {
        let text = format!(
            "{:?}",
            ConfigConsumerStatus {
                phase,
                remote_revalidated: false
            }
        );
        assert!(!text.contains("transaction"));
        assert!(!text.contains("version"));
        assert!(!text.contains("config:"));
    }
    let text = format!(
        "{}",
        ConfigConsumerError::Checkpoint(ConsumerCheckpointError::Rejected)
    );
    assert_eq!(
        text,
        "consumer checkpoint failed: consumer checkpoint validation failed"
    );
}
