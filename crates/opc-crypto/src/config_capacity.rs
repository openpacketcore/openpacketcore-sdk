//! Exact byte limits for opt-in configuration encryption.

use opc_key::{EnvelopeAad, KeyHandle, KeyProvider, KeyPurpose, AES_256_GCM_SIV_NONCE_LEN};
use rand::{rngs::SysRng, TryRng};
use serde::de::IgnoredAny;
use thiserror::Error;

use crate::{
    encrypt_envelope_with_handle_and_nonce, AuthenticatedEnvelope, ConfigPreparationReservation,
};

/// Immutable encryption byte policy. Selecting it does not enable a larger
/// store, consensus command, or transport profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigCapacityProfile {
    /// Existing envelope behavior, without bounded plaintext evidence.
    #[default]
    Legacy,
    /// Exact version-one logical, replay, AAD and envelope bounds.
    BoundedV1,
}

impl ConfigCapacityProfile {
    /// Stable policy revision; zero denotes legacy encryption.
    pub const fn revision(self) -> u16 {
        match self {
            Self::Legacy => 0,
            Self::BoundedV1 => 1,
        }
    }
}

/// Inclusive logical JSON byte limit, including adjacent value whitespace.
pub const CONFIG_CAPACITY_V1_LOGICAL_BYTES: usize = 1_572_864;
/// Inclusive replay and framing byte limit, excluding logical JSON.
pub const CONFIG_CAPACITY_V1_REPLAY_BYTES: usize = 65_536;
/// Inclusive complete plaintext limit; both constituent bounds also apply.
pub const CONFIG_CAPACITY_V1_PLAINTEXT_BYTES: usize = 1_638_400;
/// Inclusive serialized AAD limit, including the selected key binding.
pub const CONFIG_CAPACITY_V1_AAD_BYTES: usize = 65_536;
/// Inclusive complete envelope limit, including the maximum supported key ID.
pub const CONFIG_CAPACITY_V1_ENVELOPE_BYTES: usize = 1_704_492;

const CONFIG_V2_MAGIC: &[u8] = b"\x89OPCCFG\x02\r\n\x1a\n";

/// Redacted failures from bounded configuration encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfigCapacityError {
    /// Capacity unavailable, foreign pool, consumed claim or reused reservation.
    #[error("configuration preparation admission unavailable")]
    ResourceAdmission,
    /// Unsupported or ambiguous configuration JSON, framing or purpose.
    #[error("invalid configuration plaintext framing")]
    InvalidPlaintext,
    /// Logical JSON exceeds its inclusive bound.
    #[error("configuration logical byte limit exceeded")]
    LogicalBytes,
    /// Replay and framing exceed their inclusive bound.
    #[error("configuration replay byte limit exceeded")]
    ReplayBytes,
    /// Complete plaintext exceeds its inclusive bound.
    #[error("configuration plaintext byte limit exceeded")]
    PlaintextBytes,
    /// Complete bound AAD exceeds its inclusive bound.
    #[error("configuration AAD byte limit exceeded")]
    AadBytes,
    /// Complete encoded envelope exceeds its inclusive bound.
    #[error("configuration envelope byte limit exceeded")]
    EnvelopeBytes,
    /// Key selection, nonce generation or encryption failed.
    #[error("configuration encryption failed")]
    EncryptionFailed,
}

/// SDK-issued lengths for the exact plaintext of a successful encryption.
///
/// No public constructor or deserializer exists. The one-shot encryption claim
/// binds these lengths to exact ciphertext and its plaintext digest. Copying
/// lengths does not authorize another plaintext, ciphertext, key or store.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConfigCapacityEvidence {
    logical_bytes: usize,
    replay_bytes: usize,
}

impl ConfigCapacityEvidence {
    /// Policy under which the encrypted plaintext was checked.
    pub const fn profile(self) -> ConfigCapacityProfile {
        ConfigCapacityProfile::BoundedV1
    }

    /// Exact logical JSON bytes, including adjacent raw-value whitespace.
    pub const fn logical_bytes(self) -> usize {
        self.logical_bytes
    }

    /// All remaining plaintext bytes, including replay metadata and framing.
    pub const fn replay_bytes(self) -> usize {
        self.replay_bytes
    }

    fn validate(plaintext: &[u8]) -> Result<Self, ConfigCapacityError> {
        if plaintext.len() > CONFIG_CAPACITY_V1_PLAINTEXT_BYTES {
            return Err(ConfigCapacityError::PlaintextBytes);
        }
        std::str::from_utf8(plaintext.strip_prefix(CONFIG_V2_MAGIC).unwrap_or(plaintext))
            .map_err(|_| ConfigCapacityError::InvalidPlaintext)?;
        let logical_bytes = if let Some(encoded) = plaintext.strip_prefix(CONFIG_V2_MAGIC) {
            logical_bytes_v2(encoded)?
        } else {
            let _: IgnoredAny = serde_json::from_slice(plaintext)
                .map_err(|_| ConfigCapacityError::InvalidPlaintext)?;
            plaintext.len()
        };
        let replay_bytes = plaintext
            .len()
            .checked_sub(logical_bytes)
            .ok_or(ConfigCapacityError::InvalidPlaintext)?;
        if logical_bytes > CONFIG_CAPACITY_V1_LOGICAL_BYTES {
            return Err(ConfigCapacityError::LogicalBytes);
        }
        if replay_bytes > CONFIG_CAPACITY_V1_REPLAY_BYTES {
            return Err(ConfigCapacityError::ReplayBytes);
        }
        Ok(Self {
            logical_bytes,
            replay_bytes,
        })
    }

    // Keep the defensive output bound and evidence attachment in one fallible
    // constructor so successful encryption cannot bypass the checked handoff.
    fn attest(
        self,
        encoded: Vec<u8>,
        plaintext: &[u8],
    ) -> Result<AuthenticatedEnvelope, ConfigCapacityError> {
        if encoded.len() > CONFIG_CAPACITY_V1_ENVELOPE_BYTES {
            return Err(ConfigCapacityError::EnvelopeBytes);
        }
        let mut envelope = AuthenticatedEnvelope::new(encoded, plaintext);
        envelope.capacity_evidence = Some(self);
        Ok(envelope)
    }
}

impl std::fmt::Debug for ConfigCapacityEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConfigCapacityEvidence(<redacted>)")
    }
}

// Validate the complete wrapper with serde's existing struct semantics,
// including positional arrays, duplicate fields and trailing input. Values
// remain opaque: no JSON tree or second plaintext buffer is constructed.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigPlaintextV2 {
    #[serde(rename = "config")]
    _config: IgnoredAny,
    #[serde(default, rename = "source")]
    _source: Option<IgnoredAny>,
    #[serde(default, rename = "idempotency_key")]
    _idempotency_key: Option<IgnoredAny>,
    #[serde(default, rename = "apply_plan")]
    _apply_plan: Option<IgnoredAny>,
    #[serde(default, rename = "request_fingerprint")]
    _request_fingerprint: Option<IgnoredAny>,
    #[serde(default, rename = "request_id")]
    _request_id: Option<IgnoredAny>,
}

#[derive(serde::Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum ConfigField {
    Config,
    #[serde(other)]
    Replay,
}

fn take_json<'a, T: serde::Deserialize<'a>>(
    remaining: &mut &'a [u8],
) -> Result<T, ConfigCapacityError> {
    let mut stream = serde_json::Deserializer::from_slice(remaining).into_iter::<T>();
    let value = stream
        .next()
        .ok_or(ConfigCapacityError::InvalidPlaintext)?
        .map_err(|_| ConfigCapacityError::InvalidPlaintext)?;
    *remaining = &remaining[stream.byte_offset()..];
    Ok(value)
}

fn logical_bytes_v2(encoded: &[u8]) -> Result<usize, ConfigCapacityError> {
    let _: ConfigPlaintextV2 =
        serde_json::from_slice(encoded).map_err(|_| ConfigCapacityError::InvalidPlaintext)?;
    let (opening, mut remaining) = encoded
        .trim_ascii_start()
        .split_first()
        .ok_or(ConfigCapacityError::InvalidPlaintext)?;
    // Only walk the already validated outer framing. Serde parses every key
    // and value, including escapes and nested JSON, and supplies byte offsets.
    // This avoids RawValue's feature-wide change to existing Value decoders.
    loop {
        let field = if *opening == b'[' {
            ConfigField::Config
        } else {
            let field = take_json::<ConfigField>(&mut remaining)?;
            remaining = remaining
                .trim_ascii_start()
                .strip_prefix(b":")
                .ok_or(ConfigCapacityError::InvalidPlaintext)?;
            field
        };
        let before = remaining.len();
        take_json::<IgnoredAny>(&mut remaining)?;
        remaining = remaining.trim_ascii_start();
        if matches!(field, ConfigField::Config) {
            // Charge whitespace on both sides to logical bytes, just like
            // raw JSON, so it cannot borrow the independent replay budget.
            return Ok(before - remaining.len());
        }
        remaining = remaining
            .strip_prefix(b",")
            .ok_or(ConfigCapacityError::InvalidPlaintext)?;
    }
}

#[derive(Default)]
struct AadCounter {
    bytes: usize,
    exceeded: bool,
}

impl std::io::Write for AadCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let length = self
            .bytes
            .checked_add(bytes.len())
            .filter(|len| *len <= CONFIG_CAPACITY_V1_AAD_BYTES);
        let Some(length) = length else {
            self.exceeded = true;
            return Err(std::io::Error::other(
                "configuration AAD byte limit exceeded",
            ));
        };
        self.bytes = length;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn preflight_aad(aad: &EnvelopeAad) -> Result<(), ConfigCapacityError> {
    if aad.purpose() != KeyPurpose::Config {
        return Err(ConfigCapacityError::InvalidPlaintext);
    }
    // The bound representation adds a bounded key ID to this base shape.
    // Reject an oversized base before allocation or provider access.
    let mut counter = AadCounter::default();
    serde_json::to_writer(&mut counter, aad).map_err(|_| {
        if counter.exceeded {
            ConfigCapacityError::AadBytes
        } else {
            ConfigCapacityError::EncryptionFailed
        }
    })
}

fn seal(
    handle: &KeyHandle,
    aad: &EnvelopeAad,
    plaintext: &[u8],
    nonce: [u8; AES_256_GCM_SIV_NONCE_LEN],
    evidence: ConfigCapacityEvidence,
) -> Result<AuthenticatedEnvelope, ConfigCapacityError> {
    // Base preflight and KeyId's bound cap this temporary allocation even on
    // rejection. Drop it before the existing encryption encoder allocates AAD.
    let bound_aad = opc_key::serialize_bound_aad(aad, handle.key_id())
        .map_err(|_| ConfigCapacityError::EncryptionFailed)?;
    if bound_aad.len() > CONFIG_CAPACITY_V1_AAD_BYTES {
        return Err(ConfigCapacityError::AadBytes);
    }
    drop(bound_aad);
    let encoded = encrypt_envelope_with_handle_and_nonce(handle, aad, plaintext, nonce)
        .map_err(|_| ConfigCapacityError::EncryptionFailed)?;
    evidence.attest(encoded, plaintext)
}

/// Encrypt bounded JSON or an SDK version-two replay wrapper.
///
/// Limits apply to the exact borrowed plaintext, before provider access. A V2
/// wrapper starts with `\x89OPCCFG\x02\r\n\x1a\n`, then a JSON object containing
/// `config` and optional `source`, `idempotency_key`, `apply_plan`,
/// `request_fingerprint` and `request_id`, or a positional JSON array in that
/// field order. An array needs its first element; trailing optional elements
/// may be omitted. Duplicate or unknown object fields and excess array elements
/// reject. This validates byte framing, not replay metadata semantics.
///
/// The caller owns and must clear sensitive plaintext. This API does not reserve
/// preparation capacity or relax storage, RPC, memory or durability limits.
pub async fn encrypt_bounded_config_envelope<P: KeyProvider + ?Sized>(
    provider: &P,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) -> Result<AuthenticatedEnvelope, ConfigCapacityError> {
    let evidence = ConfigCapacityEvidence::validate(plaintext)?;
    preflight_aad(aad)?;
    let handle = provider
        .get_active_key(aad.purpose(), aad.tenant())
        .await
        .map_err(|_| ConfigCapacityError::EncryptionFailed)?;
    let mut nonce = [0_u8; AES_256_GCM_SIV_NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| ConfigCapacityError::EncryptionFailed)?;
    seal(&handle, aad, plaintext, nonce, evidence)
}

/// Encrypt under one destination's preparation reservation.
///
/// Consumes the reservation before provider access. Errors or cancellation drop
/// it; success retains it through the envelope and its aliases. A reservation
/// transferred out of a previous encryption claim cannot encrypt again.
/// Callers must reserve before allocating their own plaintext buffer.
pub async fn encrypt_reserved_bounded_config_envelope<P: KeyProvider + ?Sized>(
    reservation: ConfigPreparationReservation,
    provider: &P,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) -> Result<AuthenticatedEnvelope, ConfigCapacityError> {
    reservation.begin_encryption()?;
    let mut envelope = encrypt_bounded_config_envelope(provider, aad, plaintext).await?;
    envelope.preparation = Some(reservation.lease);
    Ok(envelope)
}

/// Deterministic bounded encryption for test vectors.
///
/// Callers MUST NOT reuse a nonce with the same key. Prefer
/// [`encrypt_bounded_config_envelope`] for production encryption.
pub fn encrypt_bounded_config_envelope_with_handle_and_nonce(
    handle: &KeyHandle,
    aad: &EnvelopeAad,
    plaintext: &[u8],
    nonce: [u8; AES_256_GCM_SIV_NONCE_LEN],
) -> Result<AuthenticatedEnvelope, ConfigCapacityError> {
    let evidence = ConfigCapacityEvidence::validate(plaintext)?;
    preflight_aad(aad)?;
    seal(handle, aad, plaintext, nonce, evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_envelope_encoder_checks_inclusive_output_boundary() {
        // Exercise the defensive output check independently of input bounds.
        // Public bounded encryption cannot exceed their joint maximum today.
        let mut envelope = crate::CryptoEnvelopeV1 {
            algorithm: opc_key::AeadAlgorithm::Aes256GcmSiv,
            key_id: opc_key::KeyId::new("k".repeat(512)).unwrap(),
            nonce: vec![0; AES_256_GCM_SIV_NONCE_LEN],
            aad: vec![b'a'; CONFIG_CAPACITY_V1_AAD_BYTES],
            ciphertext_and_tag: vec![0; CONFIG_CAPACITY_V1_PLAINTEXT_BYTES + opc_key::AEAD_TAG_LEN],
        };
        let at = envelope.encode().unwrap();
        assert_eq!(at.len(), CONFIG_CAPACITY_V1_ENVELOPE_BYTES);
        let evidence = ConfigCapacityEvidence::validate(b"null").unwrap();
        let attested = evidence.attest(at, b"null").unwrap();
        let claim = attested.claim().unwrap();
        assert!(claim.matches(attested.encoded()));
        assert_eq!(claim.capacity_evidence(), Some(evidence));
        envelope.ciphertext_and_tag.push(0);
        let over = envelope.encode().unwrap();
        assert_eq!(over.len(), CONFIG_CAPACITY_V1_ENVELOPE_BYTES + 1);
        assert_eq!(
            evidence.attest(over, b"null").unwrap_err(),
            ConfigCapacityError::EnvelopeBytes
        );
    }
}
