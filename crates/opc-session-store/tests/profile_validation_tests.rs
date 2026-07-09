use async_trait::async_trait;
use opc_session_store::{
    assert_backend_suitable_for_profile, validate_backend_for_profile, BackendCapabilities,
    CapabilityError, SessionBackend, SessionOp, SessionOpResult, SessionStateProfile, StateClass,
    StoreError, StoredSessionRecord,
};
use std::time::Duration;

// 1. Exhaustive property test over all 2^8 = 256 combinations of boolean capabilities.
#[test]
fn test_exhaustive_capabilities_validation() {
    for i in 0..256 {
        let caps = BackendCapabilities {
            atomic_compare_and_set: (i & 1) != 0,
            monotonic_fencing_token: (i & 2) != 0,
            per_key_ttl: (i & 4) != 0,
            server_side_lease_expiry: (i & 8) != 0,
            ordered_replication_log: (i & 16) != 0,
            batch_write: (i & 32) != 0,
            watch: (i & 64) != 0,
            restore_scan: (i & 128) != 0,
            max_value_bytes: 1024,
        };

        // Validate AuthoritativeSession
        {
            let res =
                validate_backend_for_profile(SessionStateProfile::AuthoritativeSession, &caps);
            let expected_missing: Vec<&'static str> = vec![
                (!caps.atomic_compare_and_set).then_some("atomic_compare_and_set"),
                (!caps.monotonic_fencing_token).then_some("monotonic_fencing_token"),
                (!caps.per_key_ttl).then_some("per_key_ttl"),
                (!caps.server_side_lease_expiry).then_some("server_side_lease_expiry"),
            ]
            .into_iter()
            .flatten()
            .collect();

            if expected_missing.is_empty() {
                assert!(res.is_ok());
            } else {
                match res {
                    Err(CapabilityError::MissingCapabilities { profile, missing }) => {
                        assert_eq!(profile, SessionStateProfile::AuthoritativeSession);
                        assert_eq!(missing, expected_missing);
                    }
                    _ => panic!("Expected MissingCapabilities error, got {res:?}"),
                }
            }
        }

        // Validate EphemeralProcedure
        {
            let res = validate_backend_for_profile(SessionStateProfile::EphemeralProcedure, &caps);
            let expected_missing: Vec<&'static str> = vec![
                (!caps.monotonic_fencing_token).then_some("monotonic_fencing_token"),
                (!caps.per_key_ttl).then_some("per_key_ttl"),
            ]
            .into_iter()
            .flatten()
            .collect();

            if expected_missing.is_empty() {
                assert!(res.is_ok());
            } else {
                match res {
                    Err(CapabilityError::MissingCapabilities { profile, missing }) => {
                        assert_eq!(profile, SessionStateProfile::EphemeralProcedure);
                        assert_eq!(missing, expected_missing);
                    }
                    _ => panic!("Expected MissingCapabilities error, got {res:?}"),
                }
            }
        }

        // Validate ReadThroughCache
        {
            let res = validate_backend_for_profile(SessionStateProfile::ReadThroughCache, &caps);
            let has_at_least_one = caps.watch || caps.per_key_ttl;
            if has_at_least_one {
                assert!(res.is_ok());
            } else {
                match res {
                    Err(CapabilityError::MissingCapabilities { profile, missing }) => {
                        assert_eq!(profile, SessionStateProfile::ReadThroughCache);
                        assert_eq!(missing, vec!["watch or per_key_ttl"]);
                    }
                    _ => panic!("Expected MissingCapabilities error, got {res:?}"),
                }
            }
        }

        // Validate ReplicatedDisasterRecovery
        {
            let res = validate_backend_for_profile(
                SessionStateProfile::ReplicatedDisasterRecovery,
                &caps,
            );
            let expected_missing: Vec<&'static str> = vec![
                (!caps.ordered_replication_log).then_some("ordered_replication_log"),
                (!caps.restore_scan).then_some("restore_scan"),
            ]
            .into_iter()
            .flatten()
            .collect();

            if expected_missing.is_empty() {
                assert!(res.is_ok());
            } else {
                match res {
                    Err(CapabilityError::MissingCapabilities { profile, missing }) => {
                        assert_eq!(profile, SessionStateProfile::ReplicatedDisasterRecovery);
                        assert_eq!(missing, expected_missing);
                    }
                    _ => panic!("Expected MissingCapabilities error, got {res:?}"),
                }
            }
        }
    }
}

// 2. Test assert_suitable_for and required_profile mappings for all StateClass variants.
#[test]
fn test_state_class_required_profile_mappings() {
    let all_classes = [
        (
            StateClass::AuthoritativeSession,
            SessionStateProfile::AuthoritativeSession,
        ),
        (
            StateClass::EphemeralProcedure,
            SessionStateProfile::EphemeralProcedure,
        ),
        (
            StateClass::ReplicatedDr,
            SessionStateProfile::ReplicatedDisasterRecovery,
        ),
        (
            StateClass::DataplaneLookup,
            SessionStateProfile::ReadThroughCache,
        ),
        (
            StateClass::TelemetryDerived,
            SessionStateProfile::ReadThroughCache,
        ),
    ];

    for (state_class, profile) in all_classes {
        assert_eq!(state_class.required_profile(), profile);
    }
}

// 3. Construct a customizable mock backend to verify assert_suitable_for and async helpers
struct ConfigurableMockBackend {
    caps: BackendCapabilities,
}

#[async_trait]
impl SessionBackend for ConfigurableMockBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        self.caps
    }

    async fn get(
        &self,
        _key: &opc_session_store::SessionKey,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        Ok(None)
    }

    async fn compare_and_set(
        &self,
        _op: opc_session_store::CompareAndSet,
    ) -> Result<opc_session_store::CompareAndSetResult, StoreError> {
        Err(StoreError::CasConflict)
    }

    async fn delete_fenced(
        &self,
        _lease: &opc_session_store::lease::LeaseGuard,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    async fn refresh_ttl(
        &self,
        _lease: &opc_session_store::lease::LeaseGuard,
        _ttl: Duration,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn test_async_backend_validation_helpers() {
    // A backend with zero capabilities
    let poor_backend = ConfigurableMockBackend {
        caps: BackendCapabilities::minimal(),
    };

    // Check async helper assert_backend_suitable_for_profile
    let res = assert_backend_suitable_for_profile(
        &poor_backend,
        SessionStateProfile::AuthoritativeSession,
    )
    .await;
    assert!(res.is_err());
    if let Err(CapabilityError::MissingCapabilities { profile, missing }) = res {
        assert_eq!(profile, SessionStateProfile::AuthoritativeSession);
        assert!(missing.contains(&"atomic_compare_and_set"));
    } else {
        panic!("expected CapabilityError::MissingCapabilities");
    }

    // Check trait's default assert_suitable_for method
    let res2 = poor_backend
        .assert_suitable_for(SessionStateProfile::EphemeralProcedure)
        .await;
    assert!(res2.is_err());
    if let Err(CapabilityError::MissingCapabilities { profile, missing }) = res2 {
        assert_eq!(profile, SessionStateProfile::EphemeralProcedure);
        assert!(missing.contains(&"monotonic_fencing_token"));
    } else {
        panic!("expected CapabilityError::MissingCapabilities");
    }

    // A backend with all capabilities enabled
    let rich_backend = ConfigurableMockBackend {
        caps: BackendCapabilities::all_enabled(),
    };

    assert!(assert_backend_suitable_for_profile(
        &rich_backend,
        SessionStateProfile::AuthoritativeSession
    )
    .await
    .is_ok());
    assert!(rich_backend
        .assert_suitable_for(SessionStateProfile::ReplicatedDisasterRecovery)
        .await
        .is_ok());
}
