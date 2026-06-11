use opc_crypto::{decrypt_envelope, encrypt_envelope};
use opc_key::{EnvelopeAad, KeyProvider, ShadowSecurityAad};
use opc_nacm::{
    ModuleRegistry, NacmAction, NacmEffect, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern,
};
use opc_types::{SpiffeId, TenantId};

use super::{SecurityPolicyError, SerializablePolicy, SerializableRule};

pub(crate) fn to_serializable_policy(policy: &NacmPolicy) -> SerializablePolicy {
    let version = policy.version().get();
    let mut rules = Vec::new();
    for rule in policy.rules() {
        rules.push(SerializableRule {
            action: rule.action().as_str().to_string(),
            effect: rule.effect().to_string(),
            path: rule.path().to_string(),
        });
    }
    SerializablePolicy { version, rules }
}

pub(crate) async fn encrypt_policy(
    key_provider: &dyn KeyProvider,
    tenant: &str,
    version: u64,
    policy: &SerializablePolicy,
) -> Result<Vec<u8>, SecurityPolicyError> {
    let plaintext = serde_json::to_vec(policy).map_err(|e| {
        tracing::error!(err = ?e, "Failed to serialize policy to JSON");
        SecurityPolicyError::Internal
    })?;

    let tenant_id =
        TenantId::new(tenant).map_err(|e| SecurityPolicyError::ValidationFailed(e.to_string()))?;

    let aad = EnvelopeAad::shadow_security(tenant_id, version, ShadowSecurityAad::new(version));

    let encrypted = encrypt_envelope(key_provider, &aad, &plaintext)
        .await
        .map_err(|e| {
            tracing::error!(err = ?e, "Failed to encrypt policy envelope");
            SecurityPolicyError::Internal
        })?;

    Ok(encrypted)
}

pub(crate) async fn decrypt_policy(
    key_provider: &dyn KeyProvider,
    tenant: &str,
    version: u64,
    encrypted_bytes: &[u8],
) -> Result<SerializablePolicy, SecurityPolicyError> {
    let tenant_id =
        TenantId::new(tenant).map_err(|e| SecurityPolicyError::ValidationFailed(e.to_string()))?;

    let expected_aad =
        EnvelopeAad::shadow_security(tenant_id, version, ShadowSecurityAad::new(version));

    let decrypted = decrypt_envelope(key_provider, &expected_aad, encrypted_bytes)
        .await
        .map_err(|e| {
            tracing::error!(err = ?e, "Failed to decrypt policy envelope");
            SecurityPolicyError::Internal
        })?;

    let policy: SerializablePolicy = serde_json::from_slice(&decrypted).map_err(|e| {
        tracing::error!(err = ?e, "Failed to deserialize decrypted policy");
        SecurityPolicyError::Internal
    })?;

    Ok(policy)
}

pub(crate) fn compile_serializable_policy(
    serializable: &SerializablePolicy,
) -> Result<NacmPolicy, SecurityPolicyError> {
    let mut registry = ModuleRegistry::new();
    for rule in &serializable.rules {
        for segment in rule.path.split('/') {
            if let Some((prefix, _)) = segment.split_once(':') {
                if !prefix.is_empty() && prefix != "*" {
                    let _ = registry.register_module(prefix, prefix);
                }
            }
        }
    }

    let version = PolicyVersion::new(serializable.version);
    let mut builder = NacmPolicy::builder(version);

    for rule in &serializable.rules {
        let action = rule.action.parse::<NacmAction>().map_err(|e| {
            SecurityPolicyError::ValidationFailed(format!("Invalid action: {}", e.message()))
        })?;

        let effect = match rule.effect.as_str() {
            "allow" => NacmEffect::Allow,
            "deny" => NacmEffect::Deny,
            other => {
                return Err(SecurityPolicyError::ValidationFailed(format!(
                    "Invalid effect: {}",
                    other
                )))
            }
        };

        let path_pattern = YangPathPattern::parse(&rule.path, &registry).map_err(|e| {
            SecurityPolicyError::ValidationFailed(format!("Invalid path pattern: {}", e.message()))
        })?;

        let nacm_rule = NacmRule::new(action, effect, path_pattern);
        builder = builder.add_rule(nacm_rule);
    }

    Ok(builder.build())
}

pub(crate) fn validate_principal_tenant_and_roles(
    principal_str: &str,
    target_tenant: &str,
) -> Result<(String, Vec<String>), SecurityPolicyError> {
    let (spiffe_str, mut roles) =
        if let Ok(tp) = serde_json::from_str::<serde_json::Value>(principal_str) {
            let principal_val = tp.get("principal").unwrap_or(&tp);
            let roles = principal_val
                .get("roles")
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let spiffe_str = principal_val
                .get("identity")
                .and_then(|id| id.get("Internal").or_else(|| id.get("Spiffe")))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| {
                    principal_val
                        .get("spiffe_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| principal_str.to_string())
                });

            (spiffe_str, roles)
        } else {
            let spiffe_str = principal_str.to_string();
            let roles = Vec::new();
            (spiffe_str, roles)
        };

    let spiffe = SpiffeId::new(&spiffe_str).map_err(|e| {
        SecurityPolicyError::Unauthorized(format!("Invalid SPIFFE ID: {}", e.message()))
    })?;

    let path = spiffe.path();
    let mut segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if segs.first() == Some(&"trust-domain") {
        segs.remove(0);
    }
    if segs.len() < 2 || segs[0] != "tenant" {
        return Err(SecurityPolicyError::Unauthorized(
            "Invalid SPIFFE ID layout: missing tenant".to_string(),
        ));
    }
    let parsed_tenant = segs[1];

    if parsed_tenant != target_tenant {
        return Err(SecurityPolicyError::Unauthorized(format!(
            "Tenant mismatch: principal tenant '{}' does not match target tenant '{}'",
            parsed_tenant, target_tenant
        )));
    }

    if roles.is_empty() {
        if let Some(sa_idx) = segs.iter().position(|&s| s == "sa") {
            if let Some(&sa_segment) = segs.get(sa_idx + 1) {
                if sa_segment == "security-admin" || sa_segment == "admin" {
                    roles.push("security-admin".to_string());
                }
            }
        }
    }

    Ok((spiffe_str, roles))
}
