mod lifecycle_common;

use lifecycle_common::*;
use operator_lifecycle::{generate_upgrade_plan, UpgradeAction};

#[test]
fn test_upgrade_planning_drains_sessions() {
    // Under normal ready conditions with different current and desired config versions,
    // the upgrade plan should include DeregisterFromNrf, DrainSessions, and ApplyConfig.
    let plan = generate_upgrade_plan(
        LifecyclePhase::Ready,
        true,
        &[],
        ConfigVersion::INITIAL,
        ConfigVersion::INITIAL.next().unwrap(),
        None,
        true,
        false,
        true,
    );
    assert!(!plan.is_blocked);
    assert_eq!(
        plan.actions,
        vec![
            UpgradeAction::DeregisterFromNrf,
            UpgradeAction::DrainSessions,
            UpgradeAction::ApplyConfig
        ]
    );
}
