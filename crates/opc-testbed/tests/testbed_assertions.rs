mod testbed_common;
use testbed_common::*;

#[test]
fn assertion_evaluate_basic_equality() {
    let mut state = HashMap::new();
    state.insert("amf.ue_context.state".into(), "REGISTERED".into());
    state.insert("state".into(), "INITIAL".into());

    let a1 = Assertion {
        expr: "amf.ue_context.state == REGISTERED".into(),
        order_independent: false,
    };
    assert_eq!(evaluate(&a1, &state), AssertionOutcome::Pass);

    let a2 = Assertion {
        expr: "state == INITIAL".into(),
        order_independent: false,
    };
    assert_eq!(evaluate(&a2, &state), AssertionOutcome::Pass);

    let a3 = Assertion {
        expr: "state == REGISTERED".into(),
        order_independent: false,
    };
    assert_eq!(
        evaluate(&a3, &state),
        AssertionOutcome::Fail {
            reason: "value mismatch"
        }
    );

    let a4 = Assertion {
        expr: "missing == foo".into(),
        order_independent: false,
    };
    assert_eq!(
        evaluate(&a4, &state),
        AssertionOutcome::Fail {
            reason: "key not found in context"
        }
    );
}

#[test]
fn assertion_no_last_segment_fallback() {
    let mut state = HashMap::new();
    state.insert("state".into(), "REGISTERED".into());

    let a = Assertion {
        expr: "amf.ue_context.state == REGISTERED".into(),
        order_independent: false,
    };
    assert_eq!(
        evaluate(&a, &state),
        AssertionOutcome::Fail {
            reason: "key not found in context"
        }
    );
}

#[test]
fn assertion_structured_deserialization() {
    let yaml = r#"expr: "state == REGISTERED"
order_independent: true
"#;
    let a: Assertion = serde_yaml::from_str(yaml).expect("deserialize structured assertion");
    assert_eq!(a.expr, "state == REGISTERED");
    assert!(a.order_independent);

    let yaml2 = r#"expr: "state == INITIAL"
"#;
    let a2: Assertion = serde_yaml::from_str(yaml2).expect("deserialize structured assertion");
    assert_eq!(a2.expr, "state == INITIAL");
    assert!(!a2.order_independent);
}
