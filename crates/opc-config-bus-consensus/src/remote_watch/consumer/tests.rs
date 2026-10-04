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
fn canonical_nested_values_preserve_order_escapes_and_integer_precision() {
    #[derive(Serialize)]
    struct Nested {
        z: Vec<HashMap<&'static str, u128>>,
        a: &'static str,
        empty: Vec<bool>,
        optional: Option<bool>,
        signed: i128,
    }
    let nested = Nested {
        z: vec![HashMap::from([("z", u128::MAX), ("a", 1)]), HashMap::new()],
        a: "escaped \"\\\n{}[],:é",
        empty: Vec::new(),
        optional: None,
        signed: i128::MIN,
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    assert_eq!(
        canonical_config(&nested, 1024, deadline).unwrap(),
        r#"{"a":"escaped \"\\\n{}[],:é","empty":[],"optional":null,"signed":-170141183460469231731687303715884105728,"z":[{"a":1,"z":340282366920938463463374607431768211455},{}]}"#
    );
}

#[test]
fn canonical_recursion_retains_the_existing_parser_depth_bound() {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    for depth in [127, 128] {
        let mut nested = serde_json::Value::Null;
        for _ in 0..depth {
            nested = serde_json::Value::Array(vec![nested]);
        }
        let input = serde_json::to_vec(&nested).unwrap();
        let prior = serde_json::from_slice::<serde_json::Value>(&input);
        let actual = canonical_config(&nested, 1024, deadline);
        assert_eq!(actual.is_ok(), prior.is_ok());
        assert_eq!(actual.is_ok(), depth == 127);
    }
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
