/// Capabilities that a session store backend MUST declare.
///
/// NF code MUST NOT assume semantics that the selected backend cannot provide.
/// Carrier profiles MUST reject a backend for `authoritative-session` state
/// unless it supports atomic compare-and-set and monotonic fencing tokens (or
/// an adapter that provides equivalent semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackendCapabilities {
    pub atomic_compare_and_set: bool,
    pub monotonic_fencing_token: bool,
    pub per_key_ttl: bool,
    /// Advisory: not enforced by the backend trait; consumed by carrier profile validation.
    pub server_side_lease_expiry: bool,
    /// Advisory: not enforced by the backend trait; consumed by carrier profile validation.
    pub ordered_replication_log: bool,
    pub batch_write: bool,
    /// Advisory: not enforced by the backend trait; consumed by carrier profile validation.
    pub watch: bool,
    pub max_value_bytes: usize,
}

impl BackendCapabilities {
    /// All capabilities enabled. Suitable for in-memory test backends.
    pub const fn all_enabled() -> Self {
        Self {
            atomic_compare_and_set: true,
            monotonic_fencing_token: true,
            per_key_ttl: true,
            server_side_lease_expiry: true,
            ordered_replication_log: true,
            batch_write: true,
            watch: true,
            max_value_bytes: usize::MAX,
        }
    }

    /// Minimal capability set for read-only or telemetry workloads.
    pub const fn minimal() -> Self {
        Self {
            atomic_compare_and_set: false,
            monotonic_fencing_token: false,
            per_key_ttl: false,
            server_side_lease_expiry: false,
            ordered_replication_log: false,
            batch_write: false,
            watch: false,
            max_value_bytes: 1_048_576,
        }
    }
}

pub use crate::error::CapabilityError;
use serde::{Deserialize, Serialize};

/// Target profile for session state, classifying the consistency and availability needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SessionStateProfile {
    /// Highly-consistent state requiring atomic CAS and fencing.
    AuthoritativeSession,
    /// Short-lived task state requiring fencing and auto-expiry.
    EphemeralProcedure,
    /// Stale-tolerant cache requiring invalidation or TTL bounds.
    ReadThroughCache,
    /// Region-replicated standby requiring ordered change capture.
    ReplicatedDisasterRecovery,
}

impl std::fmt::Display for SessionStateProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthoritativeSession => write!(f, "authoritative-session"),
            Self::EphemeralProcedure => write!(f, "ephemeral-procedure"),
            Self::ReadThroughCache => write!(f, "read-through-cache"),
            Self::ReplicatedDisasterRecovery => write!(f, "replicated-disaster-recovery"),
        }
    }
}

impl std::str::FromStr for SessionStateProfile {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "authoritative-session" => Ok(Self::AuthoritativeSession),
            "ephemeral-procedure" => Ok(Self::EphemeralProcedure),
            "read-through-cache" => Ok(Self::ReadThroughCache),
            "replicated-disaster-recovery" => Ok(Self::ReplicatedDisasterRecovery),
            _ => Err(format!("unknown session state profile: {}", s)),
        }
    }
}

/// Validate whether the given backend capabilities are suitable for a specific state profile.
pub fn validate_backend_for_profile(
    profile: SessionStateProfile,
    capabilities: &BackendCapabilities,
) -> Result<(), crate::error::CapabilityError> {
    let mut missing = Vec::new();
    match profile {
        SessionStateProfile::AuthoritativeSession => {
            if !capabilities.atomic_compare_and_set {
                missing.push("atomic_compare_and_set");
            }
            if !capabilities.monotonic_fencing_token {
                missing.push("monotonic_fencing_token");
            }
            if !capabilities.per_key_ttl {
                missing.push("per_key_ttl");
            }
            if !capabilities.server_side_lease_expiry {
                missing.push("server_side_lease_expiry");
            }
        }
        SessionStateProfile::EphemeralProcedure => {
            if !capabilities.monotonic_fencing_token {
                missing.push("monotonic_fencing_token");
            }
            if !capabilities.per_key_ttl {
                missing.push("per_key_ttl");
            }
        }
        SessionStateProfile::ReadThroughCache => {
            if !capabilities.watch && !capabilities.per_key_ttl {
                missing.push("watch or per_key_ttl");
            }
        }
        SessionStateProfile::ReplicatedDisasterRecovery => {
            if !capabilities.ordered_replication_log {
                missing.push("ordered_replication_log");
            }
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(crate::error::CapabilityError::MissingCapabilities { profile, missing })
    }
}

impl BackendCapabilities {
    /// Validate this capability set against a specific state profile.
    pub fn validate_for(
        &self,
        profile: SessionStateProfile,
    ) -> Result<(), crate::error::CapabilityError> {
        validate_backend_for_profile(profile, self)
    }
}

/// Assert that a backend is suitable for the given state class.
pub fn assert_suitable_for(
    state_class: crate::model::StateClass,
    capabilities: &BackendCapabilities,
) -> Result<(), crate::error::CapabilityError> {
    validate_backend_for_profile(state_class.required_profile(), capabilities)
}

/// Helper to asynchronously validate that a backend is suitable for the given profile.
pub async fn assert_backend_suitable_for_profile(
    backend: &impl crate::backend::SessionBackend,
    profile: SessionStateProfile,
) -> Result<(), crate::error::CapabilityError> {
    let caps = backend.capabilities().await;
    validate_backend_for_profile(profile, &caps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SessionBackend;
    use crate::model::StateClass;
    use crate::sqlite::SqliteSessionBackend;

    #[test]
    fn test_all_enabled_capabilities() {
        let caps = BackendCapabilities::all_enabled();
        assert!(caps
            .validate_for(SessionStateProfile::AuthoritativeSession)
            .is_ok());
        assert!(caps
            .validate_for(SessionStateProfile::EphemeralProcedure)
            .is_ok());
        assert!(caps
            .validate_for(SessionStateProfile::ReadThroughCache)
            .is_ok());
        assert!(caps
            .validate_for(SessionStateProfile::ReplicatedDisasterRecovery)
            .is_ok());
    }

    #[test]
    fn test_minimal_capabilities() {
        let caps = BackendCapabilities::minimal();

        let err = caps
            .validate_for(SessionStateProfile::AuthoritativeSession)
            .unwrap_err();
        match err {
            CapabilityError::MissingCapabilities { profile, missing } => {
                assert_eq!(profile, SessionStateProfile::AuthoritativeSession);
                assert!(missing.contains(&"atomic_compare_and_set"));
                assert!(missing.contains(&"monotonic_fencing_token"));
                assert!(missing.contains(&"per_key_ttl"));
                assert!(missing.contains(&"server_side_lease_expiry"));
            }
        }

        let err = caps
            .validate_for(SessionStateProfile::EphemeralProcedure)
            .unwrap_err();
        match err {
            CapabilityError::MissingCapabilities { profile, missing } => {
                assert_eq!(profile, SessionStateProfile::EphemeralProcedure);
                assert!(missing.contains(&"monotonic_fencing_token"));
                assert!(missing.contains(&"per_key_ttl"));
            }
        }

        let err = caps
            .validate_for(SessionStateProfile::ReadThroughCache)
            .unwrap_err();
        match err {
            CapabilityError::MissingCapabilities { profile, missing } => {
                assert_eq!(profile, SessionStateProfile::ReadThroughCache);
                assert!(missing.contains(&"watch or per_key_ttl"));
            }
        }

        let err = caps
            .validate_for(SessionStateProfile::ReplicatedDisasterRecovery)
            .unwrap_err();
        match err {
            CapabilityError::MissingCapabilities { profile, missing } => {
                assert_eq!(profile, SessionStateProfile::ReplicatedDisasterRecovery);
                assert!(missing.contains(&"ordered_replication_log"));
            }
        }
    }

    #[tokio::test]
    async fn test_sqlite_backend_suitability() {
        let backend = SqliteSessionBackend::in_memory().unwrap();

        // SQLite has CAS, monotonic fence, per-key TTL, and server-side lease expiry
        // So it is suitable for AuthoritativeSession, EphemeralProcedure, and ReadThroughCache.
        assert!(backend
            .assert_suitable_for(SessionStateProfile::AuthoritativeSession)
            .await
            .is_ok());
        assert!(backend
            .assert_suitable_for(SessionStateProfile::EphemeralProcedure)
            .await
            .is_ok());
        assert!(backend
            .assert_suitable_for(SessionStateProfile::ReadThroughCache)
            .await
            .is_ok());

        // SQLite does not have ordered_replication_log, so it is NOT suitable for ReplicatedDisasterRecovery.
        let err = backend
            .assert_suitable_for(SessionStateProfile::ReplicatedDisasterRecovery)
            .await
            .unwrap_err();
        match err {
            CapabilityError::MissingCapabilities { profile, missing } => {
                assert_eq!(profile, SessionStateProfile::ReplicatedDisasterRecovery);
                assert_eq!(missing, vec!["ordered_replication_log"]);
            }
        }

        // Test with model::StateClass mappings
        assert!(assert_suitable_for(
            StateClass::AuthoritativeSession,
            &backend.capabilities().await
        )
        .is_ok());
        assert!(assert_suitable_for(
            StateClass::EphemeralProcedure,
            &backend.capabilities().await
        )
        .is_ok());
        assert!(
            assert_suitable_for(StateClass::DataplaneLookup, &backend.capabilities().await).is_ok()
        );
        assert!(
            assert_suitable_for(StateClass::TelemetryDerived, &backend.capabilities().await)
                .is_ok()
        );

        // ReplicatedDr maps to ReplicatedDisasterRecovery, which SQLite does not support.
        assert!(
            assert_suitable_for(StateClass::ReplicatedDr, &backend.capabilities().await).is_err()
        );

        // Test assert_backend_suitable_for_profile helper
        assert!(assert_backend_suitable_for_profile(
            &backend,
            SessionStateProfile::AuthoritativeSession
        )
        .await
        .is_ok());
    }

    #[test]
    fn test_profile_display_and_from_str() {
        use std::str::FromStr;
        let cases = [
            (
                SessionStateProfile::AuthoritativeSession,
                "authoritative-session",
            ),
            (
                SessionStateProfile::EphemeralProcedure,
                "ephemeral-procedure",
            ),
            (SessionStateProfile::ReadThroughCache, "read-through-cache"),
            (
                SessionStateProfile::ReplicatedDisasterRecovery,
                "replicated-disaster-recovery",
            ),
        ];

        for (profile, s) in cases {
            assert_eq!(profile.to_string(), s);
            assert_eq!(SessionStateProfile::from_str(s).unwrap(), profile);
        }

        assert!(SessionStateProfile::from_str("unknown").is_err());
    }

    #[test]
    fn test_profile_serde() {
        let profile = SessionStateProfile::AuthoritativeSession;
        let json = serde_json::to_string(&profile).unwrap();
        assert_eq!(json, "\"authoritative-session\"");

        let round_trip: SessionStateProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, profile);
    }
}
