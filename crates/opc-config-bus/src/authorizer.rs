//! Admission-time authorization hook (RFC 001 §10): every commit, rollback,
//! and validate-only request is checked against the changed YANG paths before
//! any durable side effect; denial fails the request with
//! `AuthorizationDenied` and leaves running config untouched.

use async_trait::async_trait;
use opc_config_model::{
    CommitMode, ConfigOperation, IdempotencyKey, RequestId, RequestSource, TransportType,
    TrustedPrincipal, YangPath,
};
use opc_types::ConfigVersion;
use thiserror::Error;

/// Context presented to config authorizers.
#[derive(Debug, Clone)]
pub struct AuthorizationContext {
    /// Already-authenticated caller identity, including tenant, roles, and
    /// authentication strength; authorizers decide policy from it but must
    /// not re-authenticate.
    pub principal: TrustedPrincipal,
    /// Northbound transport the request arrived over, allowing policies that
    /// only accept writes from specific transports.
    pub transport: TransportType,
    /// Request origin (northbound, startup recovery, internal); lets
    /// policies treat operator traffic differently from recovery traffic.
    pub source: RequestSource,
    /// Requested mutation shape (replace, patch, delete, rollback) to be
    /// authorized as a distinct action per RFC 8341 semantics.
    pub operation: ConfigOperation,
    /// Commit mode of the request; validate-only requests pass through the
    /// same authorization as real commits, so denial policy cannot be probed
    /// by validation.
    pub mode: CommitMode,
    /// Every YANG path the candidate would change, computed by diffing
    /// against the running config before authorization — policies must
    /// evaluate each path, not just the request's top-level path. Empty for
    /// pre-authorized rollback admission, where paths are not yet known.
    pub changed_paths: Vec<YangPath>,
    /// Version of the running config the decision is being made against,
    /// useful for policies that pin decisions to a config generation.
    pub running_version: ConfigVersion,
    /// Correlation id of the request, so denials can be audited against the
    /// originating northbound call.
    pub request_id: RequestId,
    /// Retry-deduplication key if the caller supplied one. Idempotent
    /// replays are re-authorized with the stored changed paths, so a revoked
    /// principal cannot replay its own earlier commit.
    pub idempotency_key: Option<IdempotencyKey>,
}

/// Authorization error indicating a denied config request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("authorization denied: {message}")]
pub struct AuthorizationError {
    /// Denial detail for the authorizer's own logs. The commit pipeline
    /// discards it and returns a generic `AuthorizationDenied` to the caller,
    /// so policy internals are never leaked northbound.
    pub message: String,
}

impl AuthorizationError {
    /// Builds a denial with the given detail; remember the detail stays on
    /// the management side and is not surfaced to the requesting client.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// First-class authorization and policy admission hook.
#[async_trait]
pub trait ConfigAuthorizer: Send + Sync {
    /// Decides whether the described mutation may proceed. Called on the
    /// sequenced commit path before any durable side effect; an `Err` aborts
    /// the request with `AuthorizationDenied` and leaves the running config
    /// and store untouched. Implementations should be default-deny and must
    /// evaluate every entry in `ctx.changed_paths`.
    async fn authorize(&self, ctx: &AuthorizationContext) -> Result<(), AuthorizationError>;
}

/// A default allow-all authorizer.
#[derive(Debug, Clone, Default)]
pub struct AllowAllAuthorizer;

#[async_trait]
impl ConfigAuthorizer for AllowAllAuthorizer {
    async fn authorize(&self, _ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct DenyAllAuthorizer;

#[async_trait]
impl ConfigAuthorizer for DenyAllAuthorizer {
    async fn authorize(&self, _ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
        Err(AuthorizationError::new(
            "config mutations are disabled on this bus",
        ))
    }
}
