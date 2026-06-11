//! SBI peer identity, OAuth2/JWT-SVID validation, and pluggable
//! authorization policy (RFC 007 §9).
//!
//! The server middleware builds an `SbiAuthRequest` from each inbound
//! request (mTLS-derived peer identity plus parsed headers and bearer
//! token) and hands it to an `SbiAuth` policy; on success the resulting
//! `SbiAuthContext` is attached to the request for handlers and extractors.

mod context;
pub mod jwt;

pub use context::{ErasedAuthContext, SbiAuthContext, SbiPeer};
pub use jwt::{
    ClientTokenCache, Jwk, Jwks, JwksCache, JwksResolver, SbiJwtValidator, SvidClaims,
    TokenProvider,
};

use crate::headers::{BearerToken, SbiHeaders};
use async_trait::async_trait;
use http::Method;
use std::fmt;
use thiserror::Error;

use crate::redact::SensitiveValue;

/// Server-side auth request view passed into an SBI auth policy implementation.
#[derive(Clone, PartialEq, Eq)]
pub struct SbiAuthRequest {
    /// HTTP method of the inbound request, available so policies can apply
    /// per-operation scope rules.
    pub method: Method,
    /// Request path. Treated as sensitive (redacted in `Debug`) because SBI
    /// resource paths can embed SUPI/GPSI and other subscriber identifiers.
    pub path: String,
    /// Parsed TS 29.500 common headers for the request.
    pub headers: SbiHeaders,
    /// Bearer token from the `Authorization` header, if one was presented.
    /// `None` lets the policy decide whether anonymous access is denied.
    pub bearer_token: Option<BearerToken>,
    /// Transport-derived peer identity (from mTLS SPIFFE certificates), used
    /// for token-binding checks. Never derived from unsigned headers.
    pub peer: SbiPeer,
}

impl fmt::Debug for SbiAuthRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SbiAuthRequest")
            .field("method", &self.method)
            .field("path", &SensitiveValue)
            .field("headers", &self.headers)
            .field("bearer_token", &self.bearer_token)
            .field("peer", &self.peer)
            .finish()
    }
}

/// Authorization failure returned by an `SbiAuth` policy.
///
/// The server middleware maps `MissingBearerToken` to HTTP 401 and every
/// other variant to HTTP 403, always with a generic ProblemDetails body;
/// the `reason` strings are for internal logging/metrics, not clients, and
/// are redacted from `Debug` output.
#[derive(Clone, PartialEq, Eq, Error)]
pub enum SbiAuthError {
    /// The request presented no bearer token but the policy requires one.
    /// Maps to 401 so the client knows to (re)acquire credentials.
    #[error("missing bearer token")]
    MissingBearerToken,
    /// The transport peer identity lacks the fields (e.g. NF instance ID,
    /// tenant) the policy needs to bind the token to the caller.
    #[error("peer identity is missing required binding information")]
    MissingPeerBinding,
    /// The token's claims identify a different workload than the mTLS peer
    /// — the confused-deputy / token-replay case RFC 007 §3.1 guards
    /// against.
    #[error("bearer token binding does not match peer identity")]
    TokenBindingMismatch,
    /// Policy evaluated the request and rejected it (bad signature, expired
    /// token, audience/scope mismatch, ...).
    #[error("authorization denied")]
    Denied {
        /// Internal denial reason; must be pre-sanitized (no secrets,
        /// subscriber or tenant identifiers, or raw token material).
        reason: String,
    },
    /// The policy itself failed (e.g. JWKS refresh error), so the request
    /// is denied fail-closed rather than admitted unverified.
    #[error("internal auth failure")]
    Internal {
        /// Internal failure reason; must be pre-sanitized (no secrets,
        /// subscriber or tenant identifiers, or raw token material).
        reason: String,
    },
}

impl fmt::Debug for SbiAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBearerToken => f.write_str("MissingBearerToken"),
            Self::MissingPeerBinding => f.write_str("MissingPeerBinding"),
            Self::TokenBindingMismatch => f.write_str("TokenBindingMismatch"),
            Self::Denied { .. } => f
                .debug_struct("Denied")
                .field("reason", &SensitiveValue)
                .finish(),
            Self::Internal { .. } => f
                .debug_struct("Internal")
                .field("reason", &SensitiveValue)
                .finish(),
        }
    }
}

/// Skeleton trait for pluggable SBI authorization.
#[async_trait]
pub trait SbiAuth: Send + Sync {
    /// Implementations must ensure any `SbiAuthError::{Denied, Internal}` reason
    /// strings are safe for client/error surfaces and never contain secrets,
    /// subscriber identifiers, tenant identifiers, or raw token material.
    async fn authorize(&self, request: &SbiAuthRequest) -> Result<SbiAuthContext, SbiAuthError>;
}
