//! CRD conversion webhook helpers (GAP-009-004)
//!
//! Provides deterministic conversion between versioned custom resources (`v1alpha1` and `v1beta1`),
//! enforcing strict deserialization boundaries via `deny_unknown_fields`, sanitizing error
//! messages, and maintaining complete lifecycle status / condition mappings.
//!
//! Note: This module implements core conversion and defaulting algorithms. It does not provide
//! a live Kubernetes webhook HTTPS server out-of-the-box; such integration requires external
//! TLS certificate plumbing and HTTP server scaffolding.

use operator_lifecycle::sanitize_denial_message;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ConversionError {
    #[error("Conversion validation failed: {0}")]
    ValidationError(String),
}

impl ConversionError {
    /// Creates a new validation error with sanitized message content.
    pub fn new_validation(msg: &str) -> Self {
        Self::ValidationError(sanitize_denial_message(msg))
    }
}

pub mod v1alpha1 {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    pub struct NetworkFunctionSpec {
        pub kind: String,
        pub replicas: i32,
        pub profile: Option<String>,
        pub config_backend: Option<String>,
        pub session_backend: Option<String>,
        pub admin_token: Option<String>,
        pub token_enabled: Option<bool>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    pub struct NetworkFunctionStatus {
        pub lifecycle: Option<operator_lifecycle::LifecycleStatus>,
        pub conditions: Option<Vec<operator_lifecycle::LifecycleCondition>>,
        #[serde(alias = "observed_generation")]
        pub observed_generation: Option<i64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    pub struct NetworkFunction {
        #[serde(rename = "apiVersion", alias = "api_version")]
        pub api_version: String,
        pub kind: String,
        pub spec: NetworkFunctionSpec,
        pub status: Option<NetworkFunctionStatus>,
    }
}

pub mod v1beta1 {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    pub struct AdminAuthSpec {
        pub token_enabled: bool,
        pub admin_token: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    pub struct ResourceProfileSpec {
        pub data_plane_profile: String,
        pub numa_policy: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    pub struct NetworkFunctionSpec {
        pub kind: String,
        pub replicas: i32,
        pub profile: Option<String>,
        pub config_backend: String,
        pub session_backend: String,
        pub admin_auth: AdminAuthSpec,
        pub resource_profile: Option<ResourceProfileSpec>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    pub struct NetworkFunctionStatus {
        pub lifecycle: operator_lifecycle::LifecycleStatus,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    #[serde(rename_all = "camelCase")]
    pub struct NetworkFunction {
        #[serde(rename = "apiVersion", alias = "api_version")]
        pub api_version: String,
        pub kind: String,
        pub spec: NetworkFunctionSpec,
        pub status: Option<NetworkFunctionStatus>,
    }
}

/// Applies schema defaulting for v1alpha1 specs.
pub fn apply_defaults_v1alpha1(spec: &mut v1alpha1::NetworkFunctionSpec) {
    if spec.config_backend.is_none() {
        spec.config_backend = Some("sqlite".to_string());
    }
    if spec.session_backend.is_none() {
        spec.session_backend = Some("fake".to_string());
    }
    if spec.token_enabled.is_none() {
        spec.token_enabled = Some(false);
    }
}

/// Applies schema defaulting for v1beta1 specs.
pub fn apply_defaults_v1beta1(spec: &mut v1beta1::NetworkFunctionSpec) {
    if spec.resource_profile.is_none() {
        spec.resource_profile = Some(v1beta1::ResourceProfileSpec {
            data_plane_profile: "ControlPlaneOnly".to_string(),
            numa_policy: "Ignore".to_string(),
        });
    }
}

/// Deterministically converts a v1alpha1 resource to v1beta1.
pub fn convert_v1alpha1_to_v1beta1(
    src: &v1alpha1::NetworkFunction,
    matrix: Option<&operator_lifecycle::CompatibilityMatrix>,
) -> Result<v1beta1::NetworkFunction, ConversionError> {
    if src.api_version != "openpacketcore.org/v1alpha1" {
        return Err(ConversionError::new_validation(&format!(
            "invalid source apiVersion: {}",
            src.api_version
        )));
    }

    if let Some(m) = matrix {
        if !m.is_crd_api_version_supported(&src.api_version) {
            return Err(ConversionError::new_validation(&format!(
                "unsupported source CRD API version: {}",
                src.api_version
            )));
        }
        let target_api = "openpacketcore.org/v1beta1";
        if !m.is_crd_api_version_supported(target_api) {
            return Err(ConversionError::new_validation(&format!(
                "unsupported target CRD API version: {}",
                target_api
            )));
        }
    }

    // Unsafe validation checks
    let token_enabled = src.spec.token_enabled.unwrap_or(false);
    let admin_token = src.spec.admin_token.clone();
    if token_enabled {
        if let Some(ref token) = admin_token {
            let trimmed = token.trim();
            if trimmed.is_empty() || trimmed.len() < 16 || trimmed == "admin123" {
                return Err(ConversionError::new_validation(&format!(
                    "unsafe admin token token={} is rejected",
                    token
                )));
            }
        } else {
            return Err(ConversionError::new_validation(
                "token authentication enabled but admin_token is missing",
            ));
        }
    }

    let config_backend = src
        .spec
        .config_backend
        .clone()
        .unwrap_or_else(|| "sqlite".to_string());
    let session_backend = src
        .spec
        .session_backend
        .clone()
        .unwrap_or_else(|| "fake".to_string());

    let spec = v1beta1::NetworkFunctionSpec {
        kind: src.spec.kind.clone(),
        replicas: src.spec.replicas,
        profile: src.spec.profile.clone(),
        config_backend,
        session_backend,
        admin_auth: v1beta1::AdminAuthSpec {
            token_enabled,
            admin_token,
        },
        resource_profile: None,
    };

    // Preserve lifecycle state and conditions
    let lifecycle = if let Some(ref status) = src.status {
        status.lifecycle.clone().unwrap_or_else(|| {
            let mut ls =
                operator_lifecycle::LifecycleStatus::new(status.observed_generation.unwrap_or(0));
            if let Some(ref conds) = status.conditions {
                ls.conditions = conds.clone();
            }
            ls
        })
    } else {
        operator_lifecycle::LifecycleStatus::new(0)
    };

    Ok(v1beta1::NetworkFunction {
        api_version: "openpacketcore.org/v1beta1".to_string(),
        kind: src.kind.clone(),
        spec,
        status: Some(v1beta1::NetworkFunctionStatus { lifecycle }),
    })
}

/// Deterministically converts a v1beta1 resource to v1alpha1.
pub fn convert_v1beta1_to_v1alpha1(
    src: &v1beta1::NetworkFunction,
    matrix: Option<&operator_lifecycle::CompatibilityMatrix>,
) -> Result<v1alpha1::NetworkFunction, ConversionError> {
    if src.api_version != "openpacketcore.org/v1beta1" {
        return Err(ConversionError::new_validation(&format!(
            "invalid source apiVersion: {}",
            src.api_version
        )));
    }

    if let Some(m) = matrix {
        if !m.is_crd_api_version_supported(&src.api_version) {
            return Err(ConversionError::new_validation(&format!(
                "unsupported source CRD API version: {}",
                src.api_version
            )));
        }
        let target_api = "openpacketcore.org/v1alpha1";
        if !m.is_crd_api_version_supported(target_api) {
            return Err(ConversionError::new_validation(&format!(
                "unsupported target CRD API version: {}",
                target_api
            )));
        }
    }

    if src.spec.admin_auth.token_enabled {
        if let Some(ref token) = src.spec.admin_auth.admin_token {
            let trimmed = token.trim();
            if trimmed.is_empty() || trimmed.len() < 16 || trimmed == "admin123" {
                return Err(ConversionError::new_validation(&format!(
                    "unsafe admin token token={} is rejected",
                    token
                )));
            }
        } else {
            return Err(ConversionError::new_validation(
                "token authentication enabled but admin_token is missing",
            ));
        }
    }

    let spec = v1alpha1::NetworkFunctionSpec {
        kind: src.spec.kind.clone(),
        replicas: src.spec.replicas,
        profile: src.spec.profile.clone(),
        config_backend: Some(src.spec.config_backend.clone()),
        session_backend: Some(src.spec.session_backend.clone()),
        admin_token: src.spec.admin_auth.admin_token.clone(),
        token_enabled: Some(src.spec.admin_auth.token_enabled),
    };

    let status = src
        .status
        .as_ref()
        .map(|status| v1alpha1::NetworkFunctionStatus {
            lifecycle: Some(status.lifecycle.clone()),
            conditions: Some(status.lifecycle.conditions.clone()),
            observed_generation: Some(status.lifecycle.observed_generation),
        });

    Ok(v1alpha1::NetworkFunction {
        api_version: "openpacketcore.org/v1alpha1".to_string(),
        kind: src.kind.clone(),
        spec,
        status,
    })
}
