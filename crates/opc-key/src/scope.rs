use opc_types::{SchemaDigest, TenantId, Timestamp, TxId};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;

use crate::errors::KeyError;

const CONFIG_KDF_LABEL: &[u8] = b"openpacketcore/config/v2";
const SESSION_KDF_LABEL: &[u8] = b"openpacketcore/session/v1";
const SHADOW_SECURITY_KDF_LABEL: &[u8] = b"openpacketcore/shadow-security/v2";
const MAX_KEY_ID_LEN: usize = 512;

/// Stable key identifier carried in each encrypted envelope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct KeyId(String);

impl KeyId {
    pub fn new(value: impl Into<String>) -> Result<Self, KeyError> {
        let value = value.into();
        validate_key_id(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        KeyId::new(value).map_err(serde::de::Error::custom)
    }
}

/// Purpose-separated key lanes defined by RFC 003.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyPurpose {
    Config,
    ShadowSecurity,
    Session,
    IpsecSa,
    Audit,
    Backup,
}

impl KeyPurpose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::ShadowSecurity => "shadow-security",
            Self::Session => "session",
            Self::IpsecSa => "ipsec-sa",
            Self::Audit => "audit",
            Self::Backup => "backup",
        }
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Persisted algorithm marker stored in each envelope header.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AeadAlgorithm {
    Aes256GcmSiv,
}

impl AeadAlgorithm {
    pub const fn id(self) -> u16 {
        match self {
            Self::Aes256GcmSiv => 1,
        }
    }

    pub const fn nonce_len(self) -> usize {
        match self {
            Self::Aes256GcmSiv => 12, // AES_256_GCM_SIV_NONCE_LEN
        }
    }

    pub fn from_id(value: u16) -> Result<Self, KeyError> {
        match value {
            1 => Ok(Self::Aes256GcmSiv),
            _ => Err(KeyError::invalid_algorithm(value)),
        }
    }
}

/// Config-store metadata that must be bound into envelope AAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigAad {
    pub(crate) tx_id: TxId,
    pub(crate) parent_tx_id: Option<TxId>,
    pub(crate) committed_at: Timestamp,
    pub(crate) principal: String,
    pub(crate) schema_digest: SchemaDigest,
    pub(crate) store_kind: String,
}

impl ConfigAad {
    pub fn new(
        tx_id: TxId,
        parent_tx_id: Option<TxId>,
        committed_at: Timestamp,
        principal: impl Into<String>,
        schema_digest: SchemaDigest,
        store_kind: impl Into<String>,
    ) -> Result<Self, KeyError> {
        let aad = Self {
            tx_id,
            parent_tx_id,
            committed_at,
            principal: principal.into(),
            schema_digest,
            store_kind: store_kind.into(),
        };
        aad.validate()?;
        Ok(aad)
    }

    pub fn tx_id(&self) -> &TxId {
        &self.tx_id
    }

    pub fn parent_tx_id(&self) -> Option<&TxId> {
        self.parent_tx_id.as_ref()
    }

    pub fn committed_at(&self) -> &Timestamp {
        &self.committed_at
    }

    pub fn principal(&self) -> &str {
        &self.principal
    }

    pub fn schema_digest(&self) -> &SchemaDigest {
        &self.schema_digest
    }

    pub fn store_kind(&self) -> &str {
        &self.store_kind
    }

    pub(crate) fn validate(&self) -> Result<(), KeyError> {
        validate_non_blank_config_field("principal", &self.principal)?;
        validate_non_blank_config_field("store_kind", &self.store_kind)?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ConfigAad {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ConfigAadRepr {
            tx_id: TxId,
            parent_tx_id: Option<TxId>,
            committed_at: Timestamp,
            principal: String,
            schema_digest: SchemaDigest,
            store_kind: String,
        }

        let repr = ConfigAadRepr::deserialize(deserializer)?;
        ConfigAad::new(
            repr.tx_id,
            repr.parent_tx_id,
            repr.committed_at,
            repr.principal,
            repr.schema_digest,
            repr.store_kind,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Session-store metadata that must be bound into envelope AAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionAad {
    pub(crate) nf_kind: String,
    pub(crate) session_key_digest: String,
    pub(crate) state_type: String,
    pub(crate) generation: u64,
    pub(crate) fence: u64,
    pub(crate) backend_namespace: String,
}

impl SessionAad {
    pub fn new(
        nf_kind: impl Into<String>,
        session_key_digest: impl Into<String>,
        state_type: impl Into<String>,
        generation: u64,
        fence: u64,
        backend_namespace: impl Into<String>,
    ) -> Result<Self, KeyError> {
        let nf_kind = nf_kind.into();
        let session_key_digest = session_key_digest.into();
        let state_type = state_type.into();
        let backend_namespace = backend_namespace.into();

        let aad = Self {
            nf_kind,
            session_key_digest,
            state_type,
            generation,
            fence,
            backend_namespace,
        };
        aad.validate()?;
        Ok(aad)
    }

    pub fn nf_kind(&self) -> &str {
        &self.nf_kind
    }

    pub fn session_key_digest(&self) -> &str {
        &self.session_key_digest
    }

    pub fn state_type(&self) -> &str {
        &self.state_type
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn fence(&self) -> u64 {
        self.fence
    }

    pub fn backend_namespace(&self) -> &str {
        &self.backend_namespace
    }

    pub(crate) fn validate(&self) -> Result<(), KeyError> {
        validate_nul_free_session_field("nf_kind", &self.nf_kind)?;
        validate_nul_free_session_field("session_key_digest", &self.session_key_digest)?;
        validate_nul_free_session_field("state_type", &self.state_type)?;
        validate_nul_free_session_field("backend_namespace", &self.backend_namespace)?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for SessionAad {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SessionAadRepr {
            nf_kind: String,
            session_key_digest: String,
            state_type: String,
            generation: u64,
            fence: u64,
            backend_namespace: String,
        }

        let repr = SessionAadRepr::deserialize(deserializer)?;
        SessionAad::new(
            repr.nf_kind,
            repr.session_key_digest,
            repr.state_type,
            repr.generation,
            repr.fence,
            repr.backend_namespace,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// Shadow security policy metadata that must be bound into envelope AAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShadowSecurityAad {
    pub(crate) version: u64,
}

impl ShadowSecurityAad {
    pub fn new(version: u64) -> Self {
        Self { version }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub(crate) fn validate(&self) -> Result<(), KeyError> {
        Ok(())
    }
}

impl<'de> Deserialize<'de> for ShadowSecurityAad {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct ShadowSecurityAadRepr {
            version: u64,
        }

        let repr = ShadowSecurityAadRepr::deserialize(deserializer)?;
        Ok(ShadowSecurityAad::new(repr.version))
    }
}

/// Scope-specific metadata bound to an encrypted payload.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EnvelopeMetadata {
    Config(ConfigAad),
    Session(SessionAad),
    ShadowSecurity(ShadowSecurityAad),
}

impl EnvelopeMetadata {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::Session(_) => "session",
            Self::ShadowSecurity(_) => "shadow-security",
        }
    }

    pub(crate) fn required_purpose(&self) -> KeyPurpose {
        match self {
            Self::Config(_) => KeyPurpose::Config,
            Self::Session(_) => KeyPurpose::Session,
            Self::ShadowSecurity(_) => KeyPurpose::ShadowSecurity,
        }
    }
}

/// Public AAD model used by `opc-crypto` and downstream callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvelopeAad {
    pub(crate) tenant: TenantId,
    pub(crate) purpose: KeyPurpose,
    pub(crate) version: u64,
    pub(crate) metadata: EnvelopeMetadata,
}

impl EnvelopeAad {
    pub fn config(tenant: TenantId, version: u64, metadata: ConfigAad) -> Self {
        Self {
            tenant,
            purpose: KeyPurpose::Config,
            version,
            metadata: EnvelopeMetadata::Config(metadata),
        }
    }

    pub fn session(tenant: TenantId, version: u64, metadata: SessionAad) -> Self {
        Self {
            tenant,
            purpose: KeyPurpose::Session,
            version,
            metadata: EnvelopeMetadata::Session(metadata),
        }
    }

    pub fn shadow_security(tenant: TenantId, version: u64, metadata: ShadowSecurityAad) -> Self {
        Self {
            tenant,
            purpose: KeyPurpose::ShadowSecurity,
            version,
            metadata: EnvelopeMetadata::ShadowSecurity(metadata),
        }
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    pub const fn version(&self) -> u64 {
        self.version
    }

    pub fn metadata(&self) -> &EnvelopeMetadata {
        &self.metadata
    }

    pub(crate) fn validate(&self) -> Result<(), KeyError> {
        let expected_purpose = self.metadata.required_purpose();
        if self.purpose != expected_purpose {
            return Err(KeyError::invalid_metadata(
                "purpose",
                format!(
                    "must align with {} metadata ({})",
                    self.metadata.kind(),
                    expected_purpose.as_str()
                ),
            ));
        }

        match &self.metadata {
            EnvelopeMetadata::Config(config) => config.validate()?,
            EnvelopeMetadata::Session(session) => session.validate()?,
            EnvelopeMetadata::ShadowSecurity(shadow_security) => shadow_security.validate()?,
        }

        Ok(())
    }

    pub(crate) fn kdf_context(&self, key_id: &KeyId) -> Result<(Vec<u8>, Vec<u8>), KeyError> {
        self.validate()?;
        match &self.metadata {
            EnvelopeMetadata::Config(config) => {
                let mut salt = Vec::with_capacity(16 + config.schema_digest.as_bytes().len());
                salt.extend_from_slice(config.tx_id.as_uuid().as_bytes());
                salt.extend_from_slice(config.schema_digest.as_bytes());

                let mut info =
                    Vec::with_capacity(64 + config.store_kind.len() + key_id.as_str().len());
                info.extend_from_slice(CONFIG_KDF_LABEL);
                append_kdf_field(&mut info, config.store_kind.as_bytes());
                append_kdf_field(&mut info, key_id.as_str().as_bytes());
                Ok((salt, info))
            }
            EnvelopeMetadata::Session(session) => {
                session.validate()?;
                let mut salt = Vec::with_capacity(
                    session.session_key_digest.len() + 1 + session.state_type.len(),
                );
                salt.extend_from_slice(session.session_key_digest.as_bytes());
                salt.push(0);
                salt.extend_from_slice(session.state_type.as_bytes());

                let mut info = Vec::with_capacity(
                    64 + session.backend_namespace.len()
                        + session.nf_kind.len()
                        + key_id.as_str().len(),
                );
                info.extend_from_slice(SESSION_KDF_LABEL);
                info.push(0);
                info.extend_from_slice(self.purpose.as_str().as_bytes());
                info.push(0);
                info.extend_from_slice(session.backend_namespace.as_bytes());
                info.push(0);
                info.extend_from_slice(session.nf_kind.as_bytes());
                info.push(0);
                info.extend_from_slice(key_id.as_str().as_bytes());
                Ok((salt, info))
            }
            EnvelopeMetadata::ShadowSecurity(shadow_security) => {
                let mut salt = Vec::new();
                salt.extend_from_slice(&shadow_security.version.to_be_bytes());

                let mut info = Vec::new();
                info.extend_from_slice(SHADOW_SECURITY_KDF_LABEL);
                append_kdf_field(&mut info, key_id.as_str().as_bytes());
                Ok((salt, info))
            }
        }
    }
}

fn append_kdf_field(out: &mut Vec<u8>, value: &[u8]) {
    let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

impl<'de> Deserialize<'de> for EnvelopeAad {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct EnvelopeAadRepr {
            tenant: TenantId,
            purpose: KeyPurpose,
            version: u64,
            metadata: EnvelopeMetadata,
        }

        let repr = EnvelopeAadRepr::deserialize(deserializer)?;
        let aad = Self {
            tenant: repr.tenant,
            purpose: repr.purpose,
            version: repr.version,
            metadata: repr.metadata,
        };
        aad.validate().map_err(serde::de::Error::custom)?;
        Ok(aad)
    }
}

/// Field order is cryptographically significant because the serialized bytes
/// are bound into the envelope AAD and deterministic test vectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BoundEnvelopeAad<'a> {
    tenant: &'a TenantId,
    purpose: KeyPurpose,
    version: u64,
    key_id: &'a KeyId,
    metadata: &'a EnvelopeMetadata,
}

pub(crate) fn serialize_bound_aad(aad: &EnvelopeAad, key_id: &KeyId) -> Result<Vec<u8>, KeyError> {
    aad.validate()?;
    serde_json::to_vec(&BoundEnvelopeAad {
        tenant: &aad.tenant,
        purpose: aad.purpose,
        version: aad.version,
        key_id,
        metadata: &aad.metadata,
    })
    .map_err(|_| KeyError::invalid_metadata("aad", "failed to serialize"))
}

pub(crate) fn validate_key_id(value: &str) -> Result<(), KeyError> {
    if value.trim() != value {
        return Err(KeyError::invalid_key_id(
            "must not contain leading or trailing whitespace",
        ));
    }

    if value.is_empty() {
        return Err(KeyError::invalid_key_id("must not be empty"));
    }

    if value.len() > MAX_KEY_ID_LEN {
        return Err(KeyError::invalid_key_id("must not exceed 512 characters"));
    }

    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '/'))
    {
        return Err(KeyError::invalid_key_id(
            "must contain only ASCII alphanumeric characters or -_.:/",
        ));
    }

    Ok(())
}

fn validate_nul_free_session_field(field: &'static str, value: &str) -> Result<(), KeyError> {
    if value.contains('\0') {
        return Err(KeyError::invalid_metadata(
            field,
            "must not contain NUL bytes",
        ));
    }

    Ok(())
}

fn validate_non_blank_config_field(field: &'static str, value: &str) -> Result<(), KeyError> {
    if value.trim().is_empty() {
        return Err(KeyError::invalid_metadata(
            field,
            "must not be empty or whitespace-only",
        ));
    }

    Ok(())
}
