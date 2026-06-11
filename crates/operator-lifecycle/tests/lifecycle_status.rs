mod lifecycle_common;

use lifecycle_common::*;

#[test]
fn test_lifecycle_conditions_monotonicity() {
    let now = OffsetDateTime::now_utc();
    let mut status = LifecycleStatus::new(1);

    // 1. Add condition
    status.set_condition(
        "Ready",
        ConditionStatus::False,
        "StartingUp",
        "workload is starting up",
        1,
        ConditionSeverity::Info,
        true,
        now,
    );

    let cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(cond.status, ConditionStatus::False);
    assert_eq!(cond.last_transition_time, now);

    // 2. Attempt update with old generation (should be ignored)
    status.set_condition(
        "Ready",
        ConditionStatus::True,
        "Running",
        "workload is running",
        0, // old generation
        ConditionSeverity::Info,
        true,
        now + time::Duration::seconds(10),
    );

    let cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(cond.status, ConditionStatus::False); // status remains False

    // 3. Update status with same values but newer generation
    status.set_condition(
        "Ready",
        ConditionStatus::False,
        "StartingUp",
        "workload is starting up",
        2, // new generation
        ConditionSeverity::Info,
        true,
        now + time::Duration::seconds(20),
    );

    let cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(cond.status, ConditionStatus::False);
    assert_eq!(cond.last_transition_time, now); // transition time remains unchanged!

    // 4. Update status with different values and newer generation
    let transition_time = now + time::Duration::seconds(30);
    status.set_condition(
        "Ready",
        ConditionStatus::True,
        "Running",
        "workload is running",
        3,
        ConditionSeverity::Info,
        true,
        transition_time,
    );

    let cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(cond.status, ConditionStatus::True);
    assert_eq!(cond.last_transition_time, transition_time); // transition time updated!

    // 5. Earlier wall-clock timestamps must not move transition time backwards.
    status.set_condition(
        "Ready",
        ConditionStatus::False,
        "RegressedClock",
        "workload clock regressed",
        4,
        ConditionSeverity::Warning,
        true,
        now + time::Duration::seconds(5),
    );
    let cond = status
        .conditions
        .iter()
        .find(|c| c.r#type == "Ready")
        .unwrap();
    assert_eq!(cond.status, ConditionStatus::False);
    assert_eq!(cond.last_transition_time, transition_time);
}
