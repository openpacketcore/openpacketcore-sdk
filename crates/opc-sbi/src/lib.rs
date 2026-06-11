//! Shared SBI primitives for OpenPacketCore network functions.
//!
//! This crate provides:
//! - TS 29.500 ProblemDetails modeling,
//! - common 3GPP SBI header parsing and safe redaction,
//! - JWT-SVID authorization helpers and token caching,
//! - HTTP/2 SBI client/server builders for SDK-facing CNF code,
//! - NRF registration, heartbeat, discovery cache, and testkit helpers.

#![forbid(unsafe_code)]

pub mod auth;
pub mod client;
pub mod headers;
pub mod nrf;
pub mod problem;
mod redact;
pub mod retry;
pub mod server;

#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use auth::{
    ClientTokenCache, ErasedAuthContext, Jwk, Jwks, JwksCache, JwksResolver, SbiAuth,
    SbiAuthContext, SbiAuthError, SbiAuthRequest, SbiJwtValidator, SbiPeer, SvidClaims,
    TokenProvider,
};
pub use client::{
    CircuitBreaker, CircuitBreakers, CircuitState, ClientMiddlewareShell, DeadlineError,
    RequestDeadline, SbiClient, SbiClientBuilder,
};
pub use headers::{
    extract_bearer_token, extract_bearer_token_from_headers, AuthorizationHeader, BearerToken,
    HeaderParseError, RetryAfter, SbiHeaders, HEADER_AUTHORIZATION, HEADER_BINDING,
    HEADER_CORRELATION_INFO, HEADER_DEADLINE_HINT_MS, HEADER_IDEMPOTENCY_KEY, HEADER_LOCATION,
    HEADER_MESSAGE_PRIORITY, HEADER_RETRY_AFTER, HEADER_ROUTING_BINDING, HEADER_TARGET_API_ROOT,
};
pub use nrf::{CachedDiscoveryClient, HeartbeatDriver, NrfClient, NrfDeregNotifier, NrfOperations};
#[cfg(feature = "runtime-hooks")]
pub use nrf::{NrfDrainHook, NrfRuntimeBuilderExt};
pub use problem::{CauseCode, CauseCodeError, InvalidParam, ProblemDetails};
pub use retry::{Jitter, RetryOutcome, RetryPolicy, RetryPolicyParseError};
pub use server::{SbiExtractor, SbiExtractorData, SbiServerBuilder, ServerMiddlewareShell};
