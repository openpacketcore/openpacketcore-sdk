//! Backend capability declarations and profile validation (RFC 004 §6).
//!
//! Backends advertise what semantics they can actually provide via
//! `BackendCapabilities`; `validate_backend_for_profile` then decides whether
//! a backend may hold a given class of state. The point of the model is to
//! fail loudly at wiring time instead of silently running authoritative
//! session state on a backend that cannot fence stale owners.

/// Capabilities that a session store backend MUST declare.
///
/// NF code MUST NOT assume semantics that the selected backend cannot provide.
/// Carrier profiles MUST reject a backend for `authoritative-session` state
/// unless it supports atomic compare-and-set and monotonic fencing tokens (or
/// an adapter that provides equivalent semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Backend can perform generation-checked writes atomically on the server
    /// side (no read-modify-write race). Required for `authoritative-session`
    /// profiles; backends without it must reject `compare_and_set`.
    pub atomic_compare_and_set: bool,
    /// Backend records the highest fence token per key and rejects any write
    /// carrying a lower token (RFC 004 §9.2). Without this, a paused old
    /// owner could overwrite a newer owner after resuming, so fenced
    /// mutations must be rejected outright.
    pub monotonic_fencing_token: bool,
    /// Backend expires individual records at their `expires_at` deadline and
    /// supports fenced `refresh_ttl`. Required for `ephemeral-procedure`
    /// state, which relies on TTL to garbage-collect abandoned transactions.
    pub per_key_ttl: bool,
    /// Advisory: not enforced by the backend trait; consumed by carrier profile validation.
    pub server_side_lease_expiry: bool,
    /// Advisory: not enforced by the backend trait; consumed by carrier profile validation.
    pub ordered_replication_log: bool,
    /// Backend accepts `SessionBackend::batch`, applying the ops sequentially
    /// and reporting per-op results instead of failing the whole batch.
    pub batch_write: bool,
    /// Advisory: not enforced by the backend trait; consumed by carrier profile validation.
    pub watch: bool,
    /// Largest payload (in bytes) the backend accepts for a single record;
    /// larger writes fail with `StoreError::PayloadTooLarge` without being
    /// stored.
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

/// Platform-advertised session-store HA capability profile.
///
/// This is intentionally smaller than [`BackendCapabilities`]: it represents
/// the operator/platform profile selected for a workload, not every low-level
/// storage feature. Products should map their CRD/backend strings through
/// [`SessionStorePlatformProfile::from_backend_profile_name`] before checking
/// whether app HA state may claim traffic readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum SessionStorePlatformProfile {
    /// One authoritative replica. Suitable for lab, dev, or explicitly
    /// accepted single-replica deployments, but not for active/standby traffic
    /// readiness claims.
    SingleReplica,
    /// Quorum replicated session-store profile with ordered durable mutation
    /// semantics.
    Quorum,
    /// The platform profile name is not recognized by this SDK contract.
    Unknown,
}

impl SessionStorePlatformProfile {
    /// Parse an operator/platform backend-profile string into the SDK HA
    /// compatibility vocabulary.
    ///
    /// Unknown inputs collapse to [`Self::Unknown`] without retaining the raw
    /// text, so status paths can fail closed without leaking platform object
    /// names or deployment-specific labels.
    pub fn from_backend_profile_name(profile: &str) -> Self {
        let canonical = profile.trim().to_lowercase().replace(['_', ' '], "-");
        match canonical.as_str() {
            "single-replica"
            | "single-replica-session-store"
            | "single-node"
            | "standalone"
            | "local"
            | "sqlite"
            | "sqlite-session-store" => Self::SingleReplica,
            "quorum"
            | "quorum-session-store"
            | "quorumsessionstore"
            | "replicated-quorum"
            | "ordered-replication-log" => Self::Quorum,
            _ => Self::Unknown,
        }
    }

    /// Stable profile code for status, metrics, or evidence.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleReplica => "single-replica",
            Self::Quorum => "quorum",
            Self::Unknown => "unknown",
        }
    }
}

/// App-declared HA durability requirement for traffic-readiness claims.
///
/// Products map local HA profile names into this SDK-owned vocabulary. The SDK
/// does not decide product HA policy; it only evaluates whether the selected
/// platform session-store profile can support the durability requirement the
/// product has already chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum AppHaDurabilityRequirement {
    /// The app may claim traffic readiness on a known single-replica store.
    SingleReplicaAllowed,
    /// Active/standby app HA requires a quorum session store before traffic
    /// readiness can be claimed.
    ActiveStandby,
}

impl AppHaDurabilityRequirement {
    /// Stable requirement code for status, metrics, or evidence.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleReplicaAllowed => "single-replica-allowed",
            Self::ActiveStandby => "active-standby",
        }
    }
}

/// Compatibility outcome between app HA intent and platform session-store
/// profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum SessionStoreHaCompatibility {
    /// The platform profile satisfies the app HA durability requirement.
    Compatible,
    /// The platform profile is unknown, so readiness must fail closed until the
    /// product/operator maps it to a known SDK capability profile.
    UnknownPlatformProfile,
    /// Active/standby app HA was selected but the platform session-store
    /// profile is only single-replica.
    ActiveStandbyRequiresQuorum,
}

impl SessionStoreHaCompatibility {
    /// Whether this outcome allows traffic readiness to be claimed.
    pub const fn is_compatible(self) -> bool {
        matches!(self, Self::Compatible)
    }

    /// Whether this outcome should block traffic readiness/status claims.
    pub const fn blocks_traffic(self) -> bool {
        !self.is_compatible()
    }

    /// Stable machine-readable reason code.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::UnknownPlatformProfile => "unknown-platform-profile",
            Self::ActiveStandbyRequiresQuorum => "active-standby-requires-quorum",
        }
    }

    /// Redaction-safe operator/status message.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Compatible => "session-store profile is compatible with app HA requirement",
            Self::UnknownPlatformProfile => {
                "session-store platform profile is unknown to the SDK compatibility contract"
            }
            Self::ActiveStandbyRequiresQuorum => {
                "active-standby HA requires a quorum session-store profile before traffic readiness"
            }
        }
    }
}

/// Evaluate whether a platform session-store HA profile satisfies an app HA
/// durability requirement.
///
/// Incompatibility is a traffic-readiness/status outcome, not a platform
/// reconcile failure: callers should keep deployment reconciliation valid while
/// blocking traffic claims with [`SessionStoreHaCompatibility::reason_code`].
pub const fn evaluate_session_store_ha_compatibility(
    requirement: AppHaDurabilityRequirement,
    platform_profile: SessionStorePlatformProfile,
) -> SessionStoreHaCompatibility {
    match platform_profile {
        SessionStorePlatformProfile::Unknown => SessionStoreHaCompatibility::UnknownPlatformProfile,
        SessionStorePlatformProfile::Quorum => SessionStoreHaCompatibility::Compatible,
        SessionStorePlatformProfile::SingleReplica => match requirement {
            AppHaDurabilityRequirement::SingleReplicaAllowed => {
                SessionStoreHaCompatibility::Compatible
            }
            AppHaDurabilityRequirement::ActiveStandby => {
                SessionStoreHaCompatibility::ActiveStandbyRequiresQuorum
            }
        },
    }
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
            _ => Err(format!("unknown session state profile: {s}")),
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

    #[test]
    fn session_store_platform_profile_parses_known_aliases() {
        let single_replica_aliases = [
            "single-replica",
            "single_replica",
            "single node",
            "standalone",
            "local",
            "sqlite",
            "sqlite-session-store",
        ];
        for alias in single_replica_aliases {
            assert_eq!(
                SessionStorePlatformProfile::from_backend_profile_name(alias),
                SessionStorePlatformProfile::SingleReplica,
                "alias: {alias}"
            );
        }

        let quorum_aliases = [
            "quorum",
            "quorum-session-store",
            "quorumsessionstore",
            "replicated quorum",
            "ordered_replication_log",
        ];
        for alias in quorum_aliases {
            assert_eq!(
                SessionStorePlatformProfile::from_backend_profile_name(alias),
                SessionStorePlatformProfile::Quorum,
                "alias: {alias}"
            );
        }

        assert_eq!(
            SessionStorePlatformProfile::from_backend_profile_name("carrier-specific"),
            SessionStorePlatformProfile::Unknown
        );
    }

    #[test]
    fn session_store_ha_compatibility_blocks_active_standby_on_single_replica() {
        let outcome = evaluate_session_store_ha_compatibility(
            AppHaDurabilityRequirement::ActiveStandby,
            SessionStorePlatformProfile::SingleReplica,
        );

        assert_eq!(
            outcome,
            SessionStoreHaCompatibility::ActiveStandbyRequiresQuorum
        );
        assert!(outcome.blocks_traffic());
        assert_eq!(outcome.reason_code(), "active-standby-requires-quorum");
        assert!(
            !format!("{outcome:?}").contains("supi"),
            "debug output must stay free of product payload identifiers"
        );
    }

    #[test]
    fn session_store_ha_compatibility_allows_known_compatible_profiles() {
        assert_eq!(
            evaluate_session_store_ha_compatibility(
                AppHaDurabilityRequirement::ActiveStandby,
                SessionStorePlatformProfile::Quorum,
            ),
            SessionStoreHaCompatibility::Compatible
        );
        assert_eq!(
            evaluate_session_store_ha_compatibility(
                AppHaDurabilityRequirement::SingleReplicaAllowed,
                SessionStorePlatformProfile::SingleReplica,
            ),
            SessionStoreHaCompatibility::Compatible
        );
        assert!(!SessionStoreHaCompatibility::Compatible.blocks_traffic());
    }

    #[test]
    fn session_store_ha_compatibility_fails_closed_for_unknown_platform_profile() {
        let outcome = evaluate_session_store_ha_compatibility(
            AppHaDurabilityRequirement::SingleReplicaAllowed,
            SessionStorePlatformProfile::from_backend_profile_name("platform-prod-a"),
        );

        assert_eq!(outcome, SessionStoreHaCompatibility::UnknownPlatformProfile);
        assert!(outcome.blocks_traffic());
        assert_eq!(outcome.reason_code(), "unknown-platform-profile");
        assert!(!outcome.message().contains("platform-prod-a"));
    }

    #[test]
    fn session_store_ha_compatibility_serde_uses_stable_codes() {
        let profile = serde_json::to_string(&SessionStorePlatformProfile::SingleReplica).unwrap();
        assert_eq!(profile, "\"single-replica\"");
        let requirement =
            serde_json::to_string(&AppHaDurabilityRequirement::ActiveStandby).unwrap();
        assert_eq!(requirement, "\"active-standby\"");
        let outcome =
            serde_json::to_string(&SessionStoreHaCompatibility::ActiveStandbyRequiresQuorum)
                .unwrap();
        assert_eq!(outcome, "\"active-standby-requires-quorum\"");
    }
}
