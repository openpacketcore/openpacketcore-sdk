//! External-crate visibility check for the sealed prepared-fenced facade.

use std::sync::Arc;

use opc_key::{KeyProvider, MemoryKeyProvider, RemoteSealProvider};
use opc_session_net::{
    ActivatedSessionConsumerFencedTransitionVoters, SessionConsumerPreparedFencedTransitionBackend,
    SessionConsumerPreparedFencedTransitionBackendError,
};
use opc_session_store::PreparedFencedTransitionJournal;

fn public_persistent_constructor(
    voters: ActivatedSessionConsumerFencedTransitionVoters,
    provider: Arc<MemoryKeyProvider>,
    journal: Arc<PreparedFencedTransitionJournal>,
) -> Result<
    SessionConsumerPreparedFencedTransitionBackend,
    SessionConsumerPreparedFencedTransitionBackendError,
> {
    SessionConsumerPreparedFencedTransitionBackend::persistent_encrypting(
        voters,
        provider,
        "external-facade",
        journal,
    )
}

fn public_erased_local_constructor(
    voters: ActivatedSessionConsumerFencedTransitionVoters,
    provider: Arc<dyn KeyProvider>,
    journal: Arc<PreparedFencedTransitionJournal>,
) -> Result<
    SessionConsumerPreparedFencedTransitionBackend,
    SessionConsumerPreparedFencedTransitionBackendError,
> {
    SessionConsumerPreparedFencedTransitionBackend::persistent_encrypting(
        voters,
        provider,
        "external-erased-local-facade",
        journal,
    )
}

fn public_erased_remote_constructor(
    voters: ActivatedSessionConsumerFencedTransitionVoters,
    provider: Arc<dyn RemoteSealProvider>,
    journal: Arc<PreparedFencedTransitionJournal>,
) -> Result<
    SessionConsumerPreparedFencedTransitionBackend,
    SessionConsumerPreparedFencedTransitionBackendError,
> {
    SessionConsumerPreparedFencedTransitionBackend::persistent_remote_sealing(
        voters,
        provider,
        "external-erased-remote-facade",
        journal,
    )
}

#[test]
fn activated_roster_is_the_only_public_fenced_facade_input() {
    let _ = public_persistent_constructor
        as fn(
            ActivatedSessionConsumerFencedTransitionVoters,
            Arc<MemoryKeyProvider>,
            Arc<PreparedFencedTransitionJournal>,
        ) -> Result<
            SessionConsumerPreparedFencedTransitionBackend,
            SessionConsumerPreparedFencedTransitionBackendError,
        >;
    let _ = public_erased_local_constructor
        as fn(
            ActivatedSessionConsumerFencedTransitionVoters,
            Arc<dyn KeyProvider>,
            Arc<PreparedFencedTransitionJournal>,
        ) -> Result<
            SessionConsumerPreparedFencedTransitionBackend,
            SessionConsumerPreparedFencedTransitionBackendError,
        >;
    let _ = public_erased_remote_constructor
        as fn(
            ActivatedSessionConsumerFencedTransitionVoters,
            Arc<dyn RemoteSealProvider>,
            Arc<PreparedFencedTransitionJournal>,
        ) -> Result<
            SessionConsumerPreparedFencedTransitionBackend,
            SessionConsumerPreparedFencedTransitionBackendError,
        >;
}
