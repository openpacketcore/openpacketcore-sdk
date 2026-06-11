//! NRF (Network Repository Function) helpers for SBI discovery, caching,
//! registration, and heartbeat.
//!
//! This module provides:
//! - `DiscoveryCache`: in-memory cache for NRF discovery results with TTL,
//!   negative caching, stale-if-error fallback, and config-version invalidation.
//! - `NfProfile`, `DiscoveryQuery`, `DiscoveryResult`: typed TS 29.510 data
//!   structures used by both production code and the testkit.

pub mod cache;
pub mod client;

pub use cache::{CacheLookup, DiscoveryCache};
pub use client::{CachedDiscoveryClient, HeartbeatDriver, NrfClient, NrfOperations};

use opc_types::{NfInstanceId, NfType, PlmnId, Snssai};
use serde::{Deserialize, Serialize};

/// Status of a registered NF instance per TS 29.510.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NfStatus {
    /// NF is registered and discoverable.
    Registered,
    /// NF is temporarily suspended.
    Suspended,
    /// NF should not be returned in discovery.
    Undiscoverable,
}

/// Minimal NF profile for discovery caching and testkit fixtures.
///
/// NF-specific business logic belongs in per-NF crates; this struct captures
/// only the fields needed for SBI routing and cache keying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NfProfile {
    pub nf_instance_id: NfInstanceId,
    pub nf_type: NfType,
    pub nf_status: NfStatus,
    pub ipv4_addresses: Vec<String>,
    pub fqdn: Option<String>,
    pub plmn_list: Vec<PlmnId>,
    pub s_nssais: Vec<Snssai>,
    /// Advertised SBI service names (e.g. `nnrf-disc`, `nnssf-nsselection`).
    pub nf_services: Vec<String>,
    pub priority: u16,
    pub capacity: u16,
}

/// Query parameters for NRF discovery (TS 29.510 NFDiscovery).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryQuery {
    pub target_nf_type: NfType,
    pub requester_nf_instance_id: Option<NfInstanceId>,
    pub plmn: Option<PlmnId>,
    pub s_nssai: Option<Snssai>,
    pub service_names: Vec<String>,
}

/// Structured, collision-free cache key for discovery queries.
///
/// `service_names` are stored sorted so that equivalent queries with different
/// ordering share the same key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub target_nf_type: NfType,
    pub requester_nf_instance_id: Option<NfInstanceId>,
    pub plmn: Option<PlmnId>,
    pub s_nssai: Option<Snssai>,
    pub service_names: Vec<String>,
}

impl DiscoveryQuery {
    /// Convert this query into a structured `CacheKey`.
    ///
    /// Service names are sorted so that semantically-equivalent queries
    /// (differing only in service-name order) produce the same key.
    pub fn to_cache_key(&self) -> CacheKey {
        let mut service_names = self.service_names.clone();
        service_names.sort();
        CacheKey {
            target_nf_type: self.target_nf_type.clone(),
            requester_nf_instance_id: self.requester_nf_instance_id.clone(),
            plmn: self.plmn.clone(),
            s_nssai: self.s_nssai.clone(),
            service_names,
        }
    }
}

/// Outcome of a discovery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryResult {
    /// One or more matching NF profiles.
    Found(Vec<NfProfile>),
    /// Explicit not-found response from NRF.
    NotFound,
    /// NRF returned an error (e.g. 503, timeout).
    Error(String),
}

#[async_trait::async_trait]
pub trait NrfDeregNotifier: Send + Sync {
    /// Gracefully deregister the NF instance from the NRF.
    async fn deregister(
        &self,
        nf_instance_id: &NfInstanceId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

/// Ready-made adapter that implements `opc_runtime::shutdown::DrainHook` by delegating to an `NrfDeregNotifier`.
#[cfg(feature = "runtime-hooks")]
pub struct NrfDrainHook<N: NrfDeregNotifier> {
    notifier: std::sync::Arc<N>,
    nf_instance_id: NfInstanceId,
}

#[cfg(feature = "runtime-hooks")]
impl<N: NrfDeregNotifier> std::fmt::Debug for NrfDrainHook<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NrfDrainHook")
            .field("nf_instance_id", &self.nf_instance_id)
            .field("notifier", &"<opaque>")
            .finish()
    }
}

#[cfg(feature = "runtime-hooks")]
impl<N: NrfDeregNotifier> Clone for NrfDrainHook<N> {
    fn clone(&self) -> Self {
        Self {
            notifier: self.notifier.clone(),
            nf_instance_id: self.nf_instance_id.clone(),
        }
    }
}

#[cfg(feature = "runtime-hooks")]
impl<N: NrfDeregNotifier> NrfDrainHook<N> {
    pub fn new(notifier: std::sync::Arc<N>, nf_instance_id: NfInstanceId) -> Self {
        Self {
            notifier,
            nf_instance_id,
        }
    }
}

#[cfg(feature = "runtime-hooks")]
#[async_trait::async_trait]
impl<N: NrfDeregNotifier> opc_runtime::shutdown::DrainHook for NrfDrainHook<N> {
    fn name(&self) -> &'static str {
        "NrfDrainHook"
    }

    async fn on_drain(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.notifier.deregister(&self.nf_instance_id).await
    }
}

/// Extension trait for registering NRF hooks easily on the runtime builder.
#[cfg(feature = "runtime-hooks")]
pub trait NrfRuntimeBuilderExt {
    fn with_nrf_drain_hook<N: NrfDeregNotifier + 'static>(
        self,
        notifier: std::sync::Arc<N>,
        nf_instance_id: NfInstanceId,
    ) -> Self;
}

#[cfg(feature = "runtime-hooks")]
impl NrfRuntimeBuilderExt for opc_runtime::Builder {
    fn with_nrf_drain_hook<N: NrfDeregNotifier + 'static>(
        self,
        notifier: std::sync::Arc<N>,
        nf_instance_id: NfInstanceId,
    ) -> Self {
        self.with_drain_hook(std::sync::Arc::new(NrfDrainHook::new(
            notifier,
            nf_instance_id,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_types::{NfInstanceId, NfType};

    #[test]
    fn nrf_cache_key_no_collision_between_requester_and_service_names() {
        // These two queries must NOT produce the same cache key.
        let q1 = DiscoveryQuery {
            target_nf_type: NfType::new("amf").unwrap(),
            requester_nf_instance_id: Some(NfInstanceId::new("req1").unwrap()),
            plmn: None,
            s_nssai: None,
            service_names: vec!["svc1".into()],
        };
        let q2 = DiscoveryQuery {
            target_nf_type: NfType::new("amf").unwrap(),
            requester_nf_instance_id: None,
            plmn: None,
            s_nssai: None,
            service_names: vec!["req1".into(), "svc1".into()],
        };

        let k1 = q1.to_cache_key();
        let k2 = q2.to_cache_key();
        assert_ne!(
            k1, k2,
            "requester+single-service must not collide with no-requester+two-services"
        );
    }

    #[test]
    fn nrf_cache_key_service_name_order_is_normalized() {
        let q1 = DiscoveryQuery {
            target_nf_type: NfType::new("smf").unwrap(),
            requester_nf_instance_id: None,
            plmn: None,
            s_nssai: None,
            service_names: vec!["nsmf-pdusession".into(), "nsmf-eventexposure".into()],
        };
        let q2 = DiscoveryQuery {
            target_nf_type: NfType::new("smf").unwrap(),
            requester_nf_instance_id: None,
            plmn: None,
            s_nssai: None,
            service_names: vec!["nsmf-eventexposure".into(), "nsmf-pdusession".into()],
        };

        assert_eq!(
            q1.to_cache_key(),
            q2.to_cache_key(),
            "service name order should not affect cache key"
        );
    }

    #[cfg(feature = "runtime-hooks")]
    struct NonDebugNotifier;

    #[cfg(feature = "runtime-hooks")]
    #[async_trait::async_trait]
    impl NrfDeregNotifier for NonDebugNotifier {
        async fn deregister(
            &self,
            _nf_instance_id: &NfInstanceId,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    #[cfg(feature = "runtime-hooks")]
    #[test]
    fn nrf_drain_hook_debug_does_not_require_notifier_debug() {
        let hook = NrfDrainHook::new(
            std::sync::Arc::new(NonDebugNotifier),
            NfInstanceId::new("upf-01").unwrap(),
        );

        let rendered = format!("{hook:?}");
        assert!(rendered.contains("NrfDrainHook"));
        assert!(rendered.contains("upf-01"));
        assert!(rendered.contains("<opaque>"));
    }
}
