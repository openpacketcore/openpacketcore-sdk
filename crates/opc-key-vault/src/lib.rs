//! HashiCorp Vault Transit KMS adapter for `opc-key`.
//!
//! Implements the [`KeyProvider`] trait over Vault's Transit secrets engine
//! using the standard envelope pattern: [`KeyProvider::get_active_key`]
//! generates a fresh 256-bit data key via `datakey/plaintext` and embeds the
//! Transit-wrapped ciphertext in the returned [`KeyId`];
//! [`KeyProvider::get_key_by_id`] unwraps that ciphertext via Transit
//! `decrypt`, so the same id always yields the same key material.

#![forbid(unsafe_code)]

pub mod error;

use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use base64::Engine;
use opc_key::{
    errors::KeyError,
    provider::{KeyHandle, KeyProvider, Zeroizing},
    scope::{KeyId, KeyPurpose},
};
use opc_types::TenantId;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tracing::{error, instrument};
use url::Url;

pub use error::VaultError;

const KEY_ID_SCHEME: &str = "vault";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Vault Transit key provider.
#[derive(Clone)]
pub struct VaultKeyProvider {
    client: reqwest::Client,
    base_url: Arc<Url>,
    token: Arc<String>,
    mount_path: Arc<String>,
}

#[derive(Deserialize)]
struct VaultData<T> {
    data: T,
}

#[derive(Deserialize)]
struct DataKeyData {
    plaintext: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

impl VaultKeyProvider {
    /// Create a new provider.
    ///
    /// `base_url` must point to the Vault API root (e.g. `https://vault:8200`).
    /// `token` is the Vault token used as `X-Vault-Token`.
    /// `mount_path` is the Transit mount path (e.g. `transit`).
    pub fn new(base_url: impl Into<Url>, token: String, mount_path: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: Arc::new(base_url.into()),
            token: Arc::new(token),
            mount_path: Arc::new(mount_path),
        }
    }

    /// Authenticate using the Kubernetes auth method.
    ///
    /// Replaces the stored token with the client token returned by Vault.
    #[cfg(feature = "k8s-auth")]
    pub async fn with_kubernetes_auth(mut self, role: &str, jwt: &str) -> Result<Self, VaultError> {
        let url = self
            .base_url
            .join("v1/auth/kubernetes/login")
            .map_err(|_| VaultError::InvalidUrl)?;

        #[derive(Serialize)]
        struct LoginRequest<'a> {
            role: &'a str,
            jwt: &'a str,
        }

        let resp = self
            .client
            .post(url)
            .json(&LoginRequest { role, jwt })
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(VaultError::from)?;

        if !resp.status().is_success() {
            return Err(VaultError::AuthFailed);
        }

        #[derive(Deserialize)]
        struct Auth {
            client_token: String,
        }

        #[derive(Deserialize)]
        struct LoginResponse {
            auth: Auth,
        }

        let body: LoginResponse = resp.json().await.map_err(VaultError::from)?;
        self.token = Arc::new(body.auth.client_token);
        Ok(self)
    }

    fn key_name(purpose: KeyPurpose, tenant: &TenantId) -> String {
        format!("{}_{}", tenant.as_str(), purpose.as_str())
    }

    async fn post<B: Serialize, T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, KeyError> {
        let url = self.base_url.join(path).map_err(|_| {
            error!("invalid vault request path");
            KeyError::Unavailable
        })?;

        let resp = self
            .client
            .post(url)
            .header("X-Vault-Token", self.token.as_str())
            .json(body)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| {
                error!(error = %e, "vault request failed");
                KeyError::Unavailable
            })?;

        let status = resp.status();
        if status == StatusCode::FORBIDDEN {
            error!("vault returned 403");
            return Err(KeyError::Unavailable);
        }
        if !status.is_success() {
            error!(status = %status, "vault returned error status");
            return Err(KeyError::Unavailable);
        }

        resp.json().await.map_err(|e| {
            error!(error = %e, "failed to parse vault response");
            KeyError::Unavailable
        })
    }

    #[instrument(level = "debug", skip(self), fields(tenant = %tenant, purpose = %purpose))]
    async fn generate_data_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<(KeyId, Zeroizing<[u8; 32]>), KeyError> {
        let key_name = Self::key_name(purpose, tenant);

        #[derive(Serialize)]
        struct DataKeyRequest {
            bits: u32,
        }

        let body: VaultData<DataKeyData> = self
            .post(
                &format!("v1/{}/datakey/plaintext/{}", self.mount_path, key_name),
                &DataKeyRequest { bits: 256 },
            )
            .await?;

        let material = decode_material(&body.data.plaintext)?;
        let key_id = wrapped_key_id(&key_name, &body.data.ciphertext)?;
        Ok((key_id, material))
    }

    async fn unwrap_data_key(
        &self,
        key_name: &str,
        ciphertext: &str,
    ) -> Result<Zeroizing<[u8; 32]>, KeyError> {
        #[derive(Serialize)]
        struct DecryptRequest<'a> {
            ciphertext: &'a str,
        }

        let body: VaultData<DecryptData> = self
            .post(
                &format!("v1/{}/decrypt/{}", self.mount_path, key_name),
                &DecryptRequest { ciphertext },
            )
            .await?;

        decode_material(&body.data.plaintext)
    }
}

/// Decode base64 key material into a zeroizing 32-byte array.
fn decode_material(plaintext_b64: &str) -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let decoded = Zeroizing::new(B64_STD.decode(plaintext_b64).map_err(|_| {
        error!("vault key material was not valid base64");
        KeyError::Unavailable
    })?);

    if decoded.len() != 32 {
        error!("vault key material had unexpected length");
        return Err(KeyError::Unavailable);
    }

    let mut material = Zeroizing::new([0u8; 32]);
    material.copy_from_slice(&decoded);
    Ok(material)
}

/// Build a [`KeyId`] of the form `vault:<key_name>:<version>:<b64url(wrapped)>`
/// from a Vault Transit ciphertext (`vault:v<N>:<base64>`).
///
/// The wrapped data-key ciphertext travels inside the key id so that
/// [`KeyProvider::get_key_by_id`] can deterministically recover the same key
/// material via Transit `decrypt`.
fn wrapped_key_id(key_name: &str, vault_ciphertext: &str) -> Result<KeyId, KeyError> {
    let rest = vault_ciphertext
        .strip_prefix("vault:v")
        .ok_or_else(|| KeyError::InvalidKeyId {
            message: "unexpected vault ciphertext prefix".into(),
        })?;
    let (version, b64) = rest.split_once(':').ok_or_else(|| KeyError::InvalidKeyId {
        message: "unexpected vault ciphertext format".into(),
    })?;
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit()) {
        return Err(KeyError::InvalidKeyId {
            message: "unexpected vault ciphertext version".into(),
        });
    }
    let raw = B64_STD.decode(b64).map_err(|_| KeyError::InvalidKeyId {
        message: "vault ciphertext was not valid base64".into(),
    })?;

    KeyId::new(format!(
        "{KEY_ID_SCHEME}:{key_name}:{version}:{}",
        B64_URL.encode(raw)
    ))
}

/// Parse a `vault:<key_name>:<version>:<b64url(wrapped)>` key id back into the
/// Transit key name, purpose, tenant, and the original Vault ciphertext.
fn parse_wrapped_key_id(
    key_id: &KeyId,
) -> Result<(String, KeyPurpose, TenantId, String), KeyError> {
    let mut parts = key_id.as_str().splitn(4, ':');
    let (scheme, key_name, version, b64url) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(s), Some(n), Some(v), Some(c)) => (s, n, v, c),
            _ => {
                return Err(KeyError::InvalidKeyId {
                    message: "not a vault wrapped key id".into(),
                })
            }
        };
    if scheme != KEY_ID_SCHEME {
        return Err(KeyError::InvalidKeyId {
            message: "not a vault wrapped key id".into(),
        });
    }

    let raw = B64_URL.decode(b64url).map_err(|_| KeyError::InvalidKeyId {
        message: "wrapped data key was not valid base64url".into(),
    })?;
    let ciphertext = format!("vault:v{version}:{}", B64_STD.encode(raw));

    let (tenant_str, purpose_str) =
        key_name
            .rsplit_once('_')
            .ok_or_else(|| KeyError::InvalidKeyId {
                message: "vault key name missing purpose suffix".into(),
            })?;
    let tenant = TenantId::new(tenant_str).map_err(|_| KeyError::InvalidKeyId {
        message: "vault key name carried an invalid tenant".into(),
    })?;
    let purpose = match purpose_str {
        "config" => KeyPurpose::Config,
        "shadow-security" => KeyPurpose::ShadowSecurity,
        "session" => KeyPurpose::Session,
        "audit" => KeyPurpose::Audit,
        "backup" => KeyPurpose::Backup,
        _ => {
            return Err(KeyError::InvalidKeyId {
                message: "vault key name carried an unknown purpose".into(),
            })
        }
    };

    Ok((key_name.to_string(), purpose, tenant, ciphertext))
}

#[async_trait]
impl KeyProvider for VaultKeyProvider {
    #[instrument(level = "debug", skip(self), fields(tenant = %tenant, purpose = %purpose))]
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        let (key_id, material) = self.generate_data_key(purpose, tenant).await?;
        Ok(KeyHandle::new(key_id, purpose, tenant.clone(), material))
    }

    #[instrument(level = "debug", skip(self))]
    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        let (key_name, purpose, tenant, ciphertext) = parse_wrapped_key_id(key_id)?;
        let material = self.unwrap_data_key(&key_name, &ciphertext).await?;
        Ok(KeyHandle::new(key_id.clone(), purpose, tenant, material))
    }

    #[instrument(level = "debug", skip(self), fields(tenant = %tenant, purpose = %purpose))]
    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        let key_name = Self::key_name(purpose, tenant);

        // Rotate the wrapping key in Transit, then mint a fresh data key under
        // the new version so callers receive a post-rotation active key id.
        let url = self
            .base_url
            .join(&format!("v1/{}/keys/{}/rotate", self.mount_path, key_name))
            .map_err(|_| KeyError::RotationFailed)?;
        let resp = self
            .client
            .post(url)
            .header("X-Vault-Token", self.token.as_str())
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|e| {
                error!(error = %e, "vault rotate request failed");
                KeyError::RotationFailed
            })?;
        if !resp.status().is_success() {
            error!(status = %resp.status(), "vault rotate returned error status");
            return Err(KeyError::RotationFailed);
        }

        let (key_id, _material) = self.generate_data_key(purpose, tenant).await?;
        Ok(key_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_key_id_round_trips() {
        let wrapped = [0x5a_u8; 60];
        let ciphertext = format!("vault:v3:{}", B64_STD.encode(wrapped));
        let key_id = wrapped_key_id("tenant-a_config", &ciphertext).expect("key id");

        let (name, purpose, tenant, recovered) = parse_wrapped_key_id(&key_id).expect("parse");
        assert_eq!(name, "tenant-a_config");
        assert_eq!(purpose, KeyPurpose::Config);
        assert_eq!(tenant.as_str(), "tenant-a");
        assert_eq!(recovered, ciphertext);
    }

    #[test]
    fn rejects_foreign_key_ids() {
        let key_id = KeyId::new("tenant-a_config").expect("key id");
        assert!(matches!(
            parse_wrapped_key_id(&key_id),
            Err(KeyError::InvalidKeyId { .. })
        ));
    }

    #[test]
    fn rejects_malformed_vault_ciphertext() {
        assert!(wrapped_key_id("tenant-a_config", "not-a-vault-ciphertext").is_err());
        assert!(wrapped_key_id("tenant-a_config", "vault:vx:AAAA").is_err());
    }
}
