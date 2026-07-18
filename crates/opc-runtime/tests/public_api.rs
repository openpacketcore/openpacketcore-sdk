use std::num::NonZeroU32;
use std::time::Instant;

use opc_runtime::{
    AggregateAdmissionBudget, AggregateAdmissionConfig, ShutdownPhase, ShutdownToken,
};

#[test]
fn shutdown_phase_is_reexported_at_crate_root() {
    let token = ShutdownToken::new();
    let phase: ShutdownPhase = *token.subscribe().borrow();

    assert_eq!(phase, ShutdownPhase::Running);
}

#[test]
fn aggregate_admission_budget_is_reexported_at_crate_root() {
    let one = NonZeroU32::new(1).expect("one is non-zero");
    let budget = AggregateAdmissionBudget::new(AggregateAdmissionConfig::per_second(one, one, one));

    let permit = budget.try_acquire(Instant::now()).expect("budget admits");
    assert_eq!(budget.metrics().in_flight, 1);
    drop(permit);
    assert_eq!(budget.metrics().in_flight, 0);
}
