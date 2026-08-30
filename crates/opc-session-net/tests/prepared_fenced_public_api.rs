//! External-crate visibility check for the narrow protected fenced path.

use std::sync::Arc;

use opc_key::MemoryKeyProvider;
use opc_session_net::{
    SessionConsumerFencedTransitionBackend, SessionConsumerPreparedCheckpointBackendError,
    SessionConsumerPreparedFencedTransitionBackend,
};
use opc_session_store::{
    EncryptingSessionBackend, ProtectedFencedTransitionBackend, SessionBackend,
};

type PublicPhysical = SessionConsumerFencedTransitionBackend;
type PublicProtected = EncryptingSessionBackend<PublicPhysical, MemoryKeyProvider>;
type PublicComposite = SessionConsumerPreparedFencedTransitionBackend<PublicProtected>;

fn accepts_only_the_narrow_public_boundary<T: ProtectedFencedTransitionBackend + ?Sized>() {}

fn public_persistent_constructor(
    backend: Arc<PublicProtected>,
    voters: Vec<SessionConsumerFencedTransitionBackend>,
) -> Result<PublicComposite, SessionConsumerPreparedCheckpointBackendError> {
    SessionConsumerPreparedFencedTransitionBackend::persistent(backend, voters)
}

#[test]
fn narrow_prepared_fenced_composite_is_public_and_needs_no_lease_authority() {
    accepts_only_the_narrow_public_boundary::<PublicProtected>();
    fn assert_session_backend<T: SessionBackend>() {}
    assert_session_backend::<PublicPhysical>();

    let _ = public_persistent_constructor
        as fn(
            Arc<PublicProtected>,
            Vec<SessionConsumerFencedTransitionBackend>,
        ) -> Result<PublicComposite, SessionConsumerPreparedCheckpointBackendError>;
}
