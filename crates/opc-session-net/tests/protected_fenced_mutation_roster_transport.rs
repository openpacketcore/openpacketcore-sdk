use std::time::Duration;

use opc_session_net::{
    FencedMutationRosterTenant, PersistentFencedMutationRosterConfig,
    PersistentFencedMutationRosterConfigError, SESSION_QUORUM_CONSUMER_V3_ALPN,
    SESSION_QUORUM_CONSUMER_V3_TRANSPORT_REVISION,
};
use opc_session_store::SessionConsumerFencedMutationRosterProfile;

#[test]
fn revision_five_profile_and_alpn_are_isolated() {
    assert_eq!(SESSION_QUORUM_CONSUMER_V3_ALPN, b"opc-session-consumer/3");
    assert_eq!(SESSION_QUORUM_CONSUMER_V3_TRANSPORT_REVISION, 5);
    assert!(SessionConsumerFencedMutationRosterProfile::v1().is_exact());

    let mut mixed = SessionConsumerFencedMutationRosterProfile::v1();
    mixed.transport_revision = 4;
    assert!(!mixed.is_exact());
}

#[test]
fn fixed_roster_pool_bounds_reject_unbounded_or_empty_tenant_inputs() {
    assert_eq!(
        FencedMutationRosterTenant::new([0; 16]),
        Err(PersistentFencedMutationRosterConfigError::Capacity)
    );
    assert!(FencedMutationRosterTenant::new([1; 16]).is_ok());
    assert_eq!(
        PersistentFencedMutationRosterConfig::try_new(
            0,
            1,
            1,
            1,
            1,
            1,
            1,
            1,
            0,
            1,
            Duration::from_millis(1),
            Duration::from_millis(1),
        ),
        Err(PersistentFencedMutationRosterConfigError::Capacity)
    );
}
