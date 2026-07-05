//! # OpenPacketCore SDK
//!
//! The `opc-sdk` facade crate re-exports the core composition surface of the
//! OpenPacketCore SDK behind feature flags. A typical CNF depends on this crate
//! with the default features and brings in only what it needs.
//!
//! ## Feature map
//!
//! | Feature   | Crates pulled                              |
//! | :-------- | :----------------------------------------- |
//! | `runtime` | `opc-runtime`                              |
//! | `observability` | `opc-observability`                  |
//! | `config`  | `opc-config-bus`, `opc-config-model`       |
//! | `session` | `opc-session-store`, `opc-session-cache`   |
//! | `sbi`     | `opc-sbi`                                  |
//! | `alarm`   | `opc-alarm`                                |
//! | `identity`| `opc-identity`, `opc-tls`                  |
//! | `key`     | `opc-key`, `opc-crypto`                    |
//! | `types`   | `opc-types` (always on by default)         |
//!
//! ## Protocol codec boundary
//!
//! The facade intentionally does not re-export experimental protocol crates
//! such as `opc-proto-gtpv2c`, `opc-proto-diameter`, or `opc-proto-ikev2`,
//! and the default feature set does not pull them in. CNFs that need the
//! GTPv2-C S2b subset, the Diameter base scaffold, or the IKEv2 scaffold
//! should depend on the relevant protocol crate directly and follow its
//! `CONFORMANCE.md` boundary.
//!
//! ## Architecture in five paragraphs
//!
//! **Runtime chassis.** [`opc_runtime`] provides the process lifecycle:
//! startup phases, task supervision, health probes (`/livez`, `/readyz`,
//! `/startupz`), memory limits, and graceful SIGTERM drain. Every CNF
//! embeds this chassis.
//!
//! **Config bus.** [`opc_config_bus`] and [`opc_config_model`] implement a
//! transactional, schema-validated configuration pipeline with tenant
//! segregation, AAD-bound envelope encryption, and admission control.
//!
//! **Session store.** [`opc_session_store`] and [`opc_session_cache`] provide
//! quorum-replicated session databases with lease management, CAS operations,
//! and change-stream watches. Quorum semantics are production-grade within a
//! single process; networked replication is experimental (see `opc-session-net`).
//!
//! **Security substrate.** [`opc_identity`] and [`opc_tls`] handle SPIFFE
//! workload identity, reloadable mTLS, and certificate rotation.
//! [`opc_key`] and [`opc_crypto`] provide AEAD envelope encryption with
//! tenant-bound key providers.
//!
//! **Service-based interface.** [`opc_sbi`] supplies the shared SBI
//! client/server primitives, NRF discovery, heartbeat, retry policies, and
//! `ProblemDetails` error handling used across all 5G NFs.
//!
//! ## Prelude
//!
//! The [`prelude`] module re-exports the ~20 most-used types and traits so
//! that a typical CNF can start with:
//!
//! ```rust,no_run
//! use opc_sdk::prelude::*;
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

#[cfg(feature = "alarm")]
pub use opc_alarm;
#[cfg(feature = "config")]
pub use opc_config_bus;
#[cfg(feature = "config")]
pub use opc_config_model;
#[cfg(feature = "key")]
pub use opc_crypto;
#[cfg(feature = "identity")]
pub use opc_identity;
#[cfg(feature = "key")]
pub use opc_key;
#[cfg(feature = "observability")]
pub use opc_observability;
#[cfg(feature = "runtime")]
pub use opc_runtime;
#[cfg(feature = "sbi")]
pub use opc_sbi;
#[cfg(feature = "session")]
pub use opc_session_cache;
#[cfg(feature = "session")]
pub use opc_session_store;
#[cfg(feature = "identity")]
pub use opc_tls;
#[cfg(feature = "types")]
pub use opc_types;

/// Most-used types and traits for OpenPacketCore CNFs.
pub mod prelude {
    #[cfg(feature = "types")]
    pub use opc_types::{
        ConfigVersion, NetworkFunctionKind, NfInstanceId, NfType, PlmnId, SchemaDigest, Snssai,
        TenantId, Timestamp, TxId,
    };

    #[cfg(feature = "runtime")]
    pub use opc_runtime::{
        health::HealthResponse, Builder, Criticality, HealthModel, Readiness, RestartPolicy,
        RuntimeError, RuntimeHandle, RuntimeMode, RuntimePhase, RuntimeProfile, ShutdownToken,
        Supervisor, TaskKind, TaskName,
    };

    #[cfg(feature = "observability")]
    pub use opc_runtime::init_observability_logging;

    #[cfg(feature = "observability")]
    pub use opc_observability::{
        current_directive, init as init_tracing, set_directive, ObservabilityError,
        DEFAULT_DIRECTIVE,
    };

    #[cfg(feature = "alarm")]
    pub use opc_alarm::{
        Alarm, AlarmOpResult, AlarmType, ProbableCause, ReadinessImpact, RedactedText, Severity,
        SharedAlarmManager,
    };

    #[cfg(feature = "sbi")]
    pub use opc_sbi::{
        nrf::{NfProfile, NfStatus},
        problem::{CauseCode, ProblemDetails},
        retry::{Jitter, RetryPolicy},
        server::SbiServerBuilder,
    };

    #[cfg(feature = "config")]
    pub use opc_config_model::{
        CommitRequest, ConfigError, ConfigOperation, RequestId, TransportType, TrustedPrincipal,
        ValidationContext, WorkloadIdentity,
    };

    #[cfg(feature = "session")]
    pub use opc_session_store::{
        model::{SessionKey, SessionKeyType},
        QuorumSessionStore, SessionStoreBackend,
    };
}
