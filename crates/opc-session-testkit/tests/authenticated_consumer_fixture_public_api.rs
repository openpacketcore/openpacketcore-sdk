//! External-crate compilation check for the sealed authenticated fixture.

use std::sync::Arc;

use opc_key::KeyProvider;
use opc_session_net::SessionConsumerPreparedFencedTransitionBackend;
use opc_session_store::{
    FencedTransitionOutcome, FencedTransitionRequest, PreparedCheckpointBudget, SessionStoreBackend,
};
use opc_session_testkit::authenticated_consumer_fixture::{
    AuthenticatedPreparedFencedTransitionFacadeReopener,
    AuthenticatedPreparedFencedTransitionFixture,
    AuthenticatedPreparedFencedTransitionFixtureDiagnostics,
    AuthenticatedPreparedFencedTransitionFixtureError,
    AuthenticatedPreparedFencedTransitionFixtureGeneralBackend,
    AuthenticatedPreparedFencedTransitionFixtureSuccessorError,
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

async fn public_paired_constructor<'fixture>(
    fixture: &'fixture AuthenticatedPreparedFencedTransitionFixture,
    provider: Arc<dyn KeyProvider>,
) -> Result<
    (
        AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<dyn KeyProvider>,
        SessionConsumerPreparedFencedTransitionBackend,
        AuthenticatedPreparedFencedTransitionFacadeReopener<'fixture, dyn KeyProvider>,
    ),
    AuthenticatedPreparedFencedTransitionFixtureError,
> {
    fixture
        .open_local_aead_pair(provider, "external-fixture-pair")
        .await
        .map(|pair| pair.into_parts())
}

async fn public_fresh_process_reopen(
    reopener: &AuthenticatedPreparedFencedTransitionFacadeReopener<'_, dyn KeyProvider>,
) -> Result<
    SessionConsumerPreparedFencedTransitionBackend,
    AuthenticatedPreparedFencedTransitionFixtureError,
> {
    reopener.reopen_prepared_fenced_transition_facade().await
}

async fn public_semantic_successor_control(
    reopener: &AuthenticatedPreparedFencedTransitionFacadeReopener<'_, dyn KeyProvider>,
    request: FencedTransitionRequest,
    budget: PreparedCheckpointBudget,
) -> Result<FencedTransitionOutcome, AuthenticatedPreparedFencedTransitionFixtureSuccessorError> {
    reopener
        .advance_authoritative_successor(request, budget)
        .await
}

fn assert_session_store_backend<T: SessionStoreBackend>() {}

#[test]
fn external_consumer_can_use_only_the_opaque_facade_and_redacted_diagnostics() {
    let _ = public_local_aead_constructor;
    let _ = public_paired_constructor;
    let _ = public_fresh_process_reopen;
    let _ = public_semantic_successor_control;
    let _ = public_diagnostics;
    let _ = public_status_miss_round_control;
    assert_session_store_backend::<
        AuthenticatedPreparedFencedTransitionFixtureGeneralBackend<dyn KeyProvider>,
    >();
}
