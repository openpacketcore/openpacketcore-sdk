//! External-crate compilation check for the sealed authenticated fixture.

use std::sync::Arc;

use opc_key::KeyProvider;
use opc_session_net::SessionConsumerPreparedFencedTransitionBackend;
use opc_session_testkit::authenticated_consumer_fixture::{
    AuthenticatedPreparedFencedTransitionFixture,
    AuthenticatedPreparedFencedTransitionFixtureDiagnostics,
    AuthenticatedPreparedFencedTransitionFixtureError,
};

async fn public_local_aead_constructor(
    fixture: &AuthenticatedPreparedFencedTransitionFixture,
    provider: Arc<dyn KeyProvider>,
) -> Result<
    SessionConsumerPreparedFencedTransitionBackend,
    AuthenticatedPreparedFencedTransitionFixtureError,
> {
    fixture
        .open_local_aead(provider, "external-fixture-consumer")
        .await
}

fn public_diagnostics(
    fixture: &AuthenticatedPreparedFencedTransitionFixture,
) -> AuthenticatedPreparedFencedTransitionFixtureDiagnostics {
    fixture.diagnostics()
}

fn public_status_miss_round_control(fixture: &AuthenticatedPreparedFencedTransitionFixture) {
    fixture.force_next_fenced_transition_status_round_to_miss();
    let _ = fixture
        .diagnostics()
        .forced_fenced_transition_status_misses();
}

#[test]
fn external_consumer_can_use_only_the_opaque_facade_and_redacted_diagnostics() {
    let _ = public_local_aead_constructor;
    let _ = public_diagnostics;
    let _ = public_status_miss_round_control;
}
