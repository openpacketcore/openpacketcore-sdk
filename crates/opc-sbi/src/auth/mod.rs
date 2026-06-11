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
    pub method: Method,
    pub path: String,
    pub headers: SbiHeaders,
    pub bearer_token: Option<BearerToken>,
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

#[derive(Clone, PartialEq, Eq, Error)]
pub enum SbiAuthError {
    #[error("missing bearer token")]
    MissingBearerToken,
    #[error("peer identity is missing required binding information")]
    MissingPeerBinding,
    #[error("bearer token binding does not match peer identity")]
    TokenBindingMismatch,
    #[error("authorization denied")]
    Denied { reason: String },
    #[error("internal auth failure")]
    Internal { reason: String },
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
