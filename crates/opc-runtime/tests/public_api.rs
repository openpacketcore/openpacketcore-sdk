use opc_runtime::{ShutdownPhase, ShutdownToken};

#[test]
fn shutdown_phase_is_reexported_at_crate_root() {
    let token = ShutdownToken::new();
    let phase: ShutdownPhase = *token.subscribe().borrow();

    assert_eq!(phase, ShutdownPhase::Running);
}
