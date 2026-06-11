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
    pub principal: TrustedPrincipal,
    pub transport: TransportType,
    pub source: RequestSource,
    pub operation: ConfigOperation,
    pub mode: CommitMode,
    pub changed_paths: Vec<YangPath>,
    pub running_version: ConfigVersion,
    pub request_id: RequestId,
    pub idempotency_key: Option<IdempotencyKey>,
}

/// Authorization error indicating a denied config request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("authorization denied: {message}")]
pub struct AuthorizationError {
    pub message: String,
}

impl AuthorizationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// First-class authorization and policy admission hook.
#[async_trait]
pub trait ConfigAuthorizer: Send + Sync {
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
