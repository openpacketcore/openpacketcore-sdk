//! IKEv2 protected-payload decryption helpers for SA_INIT-derived keys.
//!
//! @spec IETF RFC5282 3; IETF RFC7296 3.14
//! @req REQ-IETF-RFC5282-AES-GCM-PROTECTED-PAYLOAD-001

use std::{error::Error, fmt};

use aes_gcm::{
    aead::{Aead, Key, KeyInit, Nonce, Payload},
    Aes128Gcm, Aes256Gcm,
};
use bytes::Bytes;

use crate::{
    crypto::{CryptoProvider, ProtectedPayloadContext, ProtectedPayloadKind},
    payload::GENERIC_PAYLOAD_HEADER_LEN,
    sa_init_crypto::{Ikev2EncryptionAlgorithm, Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial},
    HEADER_LEN,
};

const AES_GCM_SALT_LEN: usize = 4;
const AES_GCM_EXPLICIT_IV_LEN: usize = 8;
const AES_GCM_ICV_LEN: usize = 16;
const AES_128_KEY_LEN: usize = 16;
const AES_256_KEY_LEN: usize = 32;

/// Direction of an IKEv2 protected message on an established IKE SA.
///
/// The direction selects the initiator or responder encryption/authentication
/// key material from the RFC 7296 key stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2ProtectedPayloadDirection {
    /// Packet sent by the IKE SA initiator and opened with `SK_ei`/`SK_ai`.
    InitiatorToResponder,
    /// Packet sent by the IKE SA responder and opened with `SK_er`/`SK_ar`.
    ResponderToInitiator,
}

impl Ikev2ProtectedPayloadDirection {
    const fn encryption_key_name(self) -> &'static str {
        match self {
            Self::InitiatorToResponder => "SK_ei",
            Self::ResponderToInitiator => "SK_er",
        }
    }

    const fn integrity_key_name(self) -> &'static str {
        match self {
            Self::InitiatorToResponder => "SK_ai",
            Self::ResponderToInitiator => "SK_ar",
        }
    }
}

/// Stable machine-readable protected-payload crypto error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2ProtectedPayloadCryptoErrorCode {
    /// Protected payload kind is not supported by this helper.
    UnsupportedProtectedPayloadKind,
    /// The supplied SA_INIT profile is not supported by this helper.
    UnsupportedEncryptionProfile,
    /// Key material length does not match the negotiated profile.
    InvalidKeyMaterialLength,
    /// Protected payload body is too short to contain IV and ICV.
    ProtectedPayloadTooShort,
    /// The protected payload offset or length is inconsistent with the message.
    InvalidAssociatedData,
    /// AES-GCM authentication failed.
    AuthenticationFailed,
    /// Decrypted IKE padding is structurally invalid.
    InvalidPadding,
}

impl Ikev2ProtectedPayloadCryptoErrorCode {
    /// Stable machine-readable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedProtectedPayloadKind => {
                "ike_protected_payload_crypto_unsupported_kind"
            }
            Self::UnsupportedEncryptionProfile => {
                "ike_protected_payload_crypto_unsupported_profile"
            }
            Self::InvalidKeyMaterialLength => "ike_protected_payload_crypto_invalid_key_length",
            Self::ProtectedPayloadTooShort => "ike_protected_payload_crypto_body_too_short",
            Self::InvalidAssociatedData => "ike_protected_payload_crypto_invalid_aad",
            Self::AuthenticationFailed => "ike_protected_payload_crypto_authentication_failed",
            Self::InvalidPadding => "ike_protected_payload_crypto_invalid_padding",
        }
    }
}

/// Error returned by the SA_INIT protected-payload decrypting helper.
///
/// `Debug` and `Display` intentionally report only structural metadata. They
/// never include nonce, key, ciphertext, tag, decrypted cleartext, or AUTH bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2ProtectedPayloadCryptoError {
    /// Protected payload kind is unsupported.
    UnsupportedProtectedPayloadKind {
        /// Protected payload kind observed at the crypto boundary.
        kind: ProtectedPayloadKind,
    },
    /// Encryption/integrity profile is unsupported.
    UnsupportedEncryptionProfile {
        /// Negotiated encryption algorithm.
        encryption: Ikev2EncryptionAlgorithm,
        /// Negotiated integrity key length in octets.
        integrity_key_len: usize,
    },
    /// A selected key had the wrong length.
    InvalidKeyMaterialLength {
        /// Redaction-safe key label.
        name: &'static str,
        /// Expected length in octets.
        expected: usize,
        /// Actual length in octets.
        actual: usize,
    },
    /// Protected payload body was too short.
    ProtectedPayloadTooShort {
        /// Minimum required protected body length.
        min_len: usize,
        /// Actual protected body length.
        actual: usize,
    },
    /// Protected payload associated-data inputs were inconsistent.
    InvalidAssociatedData,
    /// AES-GCM authentication failed.
    AuthenticationFailed,
    /// IKE padding was structurally invalid after authenticated decryption.
    InvalidPadding {
        /// Decrypted plaintext length in octets.
        plaintext_len: usize,
        /// Pad length octet value.
        pad_len: usize,
    },
}

impl Ikev2ProtectedPayloadCryptoError {
    /// Stable machine-readable error code.
    pub const fn code(&self) -> Ikev2ProtectedPayloadCryptoErrorCode {
        match self {
            Self::UnsupportedProtectedPayloadKind { .. } => {
                Ikev2ProtectedPayloadCryptoErrorCode::UnsupportedProtectedPayloadKind
            }
            Self::UnsupportedEncryptionProfile { .. } => {
                Ikev2ProtectedPayloadCryptoErrorCode::UnsupportedEncryptionProfile
            }
            Self::InvalidKeyMaterialLength { .. } => {
                Ikev2ProtectedPayloadCryptoErrorCode::InvalidKeyMaterialLength
            }
            Self::ProtectedPayloadTooShort { .. } => {
                Ikev2ProtectedPayloadCryptoErrorCode::ProtectedPayloadTooShort
            }
            Self::InvalidAssociatedData => {
                Ikev2ProtectedPayloadCryptoErrorCode::InvalidAssociatedData
            }
            Self::AuthenticationFailed => {
                Ikev2ProtectedPayloadCryptoErrorCode::AuthenticationFailed
            }
            Self::InvalidPadding { .. } => Ikev2ProtectedPayloadCryptoErrorCode::InvalidPadding,
        }
    }

    /// Stable machine-readable error code string.
    pub const fn as_str(&self) -> &'static str {
        self.code().as_str()
    }
}

impl fmt::Display for Ikev2ProtectedPayloadCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedProtectedPayloadKind { kind } => {
                write!(f, "unsupported IKEv2 protected payload kind {kind:?}")
            }
            Self::UnsupportedEncryptionProfile {
                encryption,
                integrity_key_len,
            } => {
                write!(
                    f,
                    "unsupported IKEv2 protected payload profile {} with integrity key length {integrity_key_len}",
                    encryption.name()
                )
            }
            Self::InvalidKeyMaterialLength {
                name,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "invalid IKEv2 protected payload {name} length: expected {expected}, actual {actual}"
                )
            }
            Self::ProtectedPayloadTooShort { min_len, actual } => {
                write!(
                    f,
                    "IKEv2 protected payload body too short: minimum {min_len}, actual {actual}"
                )
            }
            Self::InvalidAssociatedData => {
                f.write_str("IKEv2 protected payload associated data is inconsistent")
            }
            Self::AuthenticationFailed => {
                f.write_str("IKEv2 protected payload authentication failed")
            }
            Self::InvalidPadding {
                plaintext_len,
                pad_len,
            } => {
                write!(
                    f,
                    "invalid IKEv2 protected payload padding: plaintext length {plaintext_len}, pad length {pad_len}"
                )
            }
        }
    }
}

impl Error for Ikev2ProtectedPayloadCryptoError {}

/// Concrete [`CryptoProvider`] for IKEv2 AES-GCM SK payloads.
///
/// This provider owns no SA state. Callers pass the already-selected SA_INIT
/// crypto profile, derived key material, and packet direction for one open.
#[derive(Debug, Clone, Copy)]
pub struct Ikev2SaInitProtectedPayloadProvider<'a> {
    profile: Ikev2SaInitCryptoProfile,
    key_material: &'a Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
}

impl<'a> Ikev2SaInitProtectedPayloadProvider<'a> {
    /// Build a provider for one IKE SA key set and packet direction.
    pub const fn new(
        profile: Ikev2SaInitCryptoProfile,
        key_material: &'a Ikev2SaInitKeyMaterial,
        direction: Ikev2ProtectedPayloadDirection,
    ) -> Self {
        Self {
            profile,
            key_material,
            direction,
        }
    }

    /// Negotiated SA_INIT crypto profile used by this provider.
    pub const fn profile(self) -> Ikev2SaInitCryptoProfile {
        self.profile
    }

    /// Packet direction used to select initiator or responder keys.
    pub const fn direction(self) -> Ikev2ProtectedPayloadDirection {
        self.direction
    }
}

impl CryptoProvider for Ikev2SaInitProtectedPayloadProvider<'_> {
    type Error = Ikev2ProtectedPayloadCryptoError;

    fn open_payload(
        &self,
        context: ProtectedPayloadContext<'_>,
        protected_body: &[u8],
    ) -> Result<Bytes, Self::Error> {
        decrypt_ikev2_sa_init_protected_payload(
            self.profile,
            self.key_material,
            self.direction,
            context,
            protected_body,
        )
    }
}

/// Authenticate and decrypt one IKEv2 `SK` payload body with SA_INIT keys.
///
/// The helper supports RFC 5282 `ENCR_AES_GCM_16` profiles with 128-bit or
/// 256-bit AES keys. It uses `SK_ei`/`SK_ai` for
/// [`Ikev2ProtectedPayloadDirection::InitiatorToResponder`] and
/// `SK_er`/`SK_ar` for
/// [`Ikev2ProtectedPayloadDirection::ResponderToInitiator`].
///
/// # Errors
///
/// Returns [`Ikev2ProtectedPayloadCryptoError`] when the profile, keys, body,
/// associated data, AEAD authentication, or decrypted IKE padding is invalid.
pub fn decrypt_ikev2_sa_init_protected_payload(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    context: ProtectedPayloadContext<'_>,
    protected_body: &[u8],
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
    if context.kind != ProtectedPayloadKind::Encrypted {
        return Err(
            Ikev2ProtectedPayloadCryptoError::UnsupportedProtectedPayloadKind {
                kind: context.kind,
            },
        );
    }
    validate_profile(profile)?;

    let keys = select_keys(profile, key_material, direction)?;
    let aad = protected_payload_aad(context, protected_body)?;
    let plaintext = decrypt_aes_gcm(profile.encryption(), keys, aad, protected_body)?;
    strip_ike_padding(plaintext)
}

struct SelectedProtectedPayloadKeys<'a> {
    encryption_key: &'a [u8],
    salt: &'a [u8],
}

fn validate_profile(
    profile: Ikev2SaInitCryptoProfile,
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    if profile.integrity_key_len() != 0 {
        return Err(
            Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile {
                encryption: profile.encryption(),
                integrity_key_len: profile.integrity_key_len(),
            },
        );
    }

    Ok(())
}

fn select_keys<'a>(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &'a Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
) -> Result<SelectedProtectedPayloadKeys<'a>, Ikev2ProtectedPayloadCryptoError> {
    let (sk_e, sk_a) = match direction {
        Ikev2ProtectedPayloadDirection::InitiatorToResponder => {
            (key_material.sk_ei(), key_material.sk_ai())
        }
        Ikev2ProtectedPayloadDirection::ResponderToInitiator => {
            (key_material.sk_er(), key_material.sk_ar())
        }
    };

    validate_key_len(
        direction.integrity_key_name(),
        profile.integrity_key_len(),
        sk_a.len(),
    )?;

    let expected_sk_e_len = profile.encryption().key_material_len();
    validate_key_len(
        direction.encryption_key_name(),
        expected_sk_e_len,
        sk_e.len(),
    )?;
    let encryption_key_len = expected_sk_e_len.checked_sub(AES_GCM_SALT_LEN).ok_or(
        Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
            name: direction.encryption_key_name(),
            expected: expected_sk_e_len,
            actual: sk_e.len(),
        },
    )?;
    let (encryption_key, salt) = sk_e.split_at(encryption_key_len);

    Ok(SelectedProtectedPayloadKeys {
        encryption_key,
        salt,
    })
}

fn validate_key_len(
    name: &'static str,
    expected: usize,
    actual: usize,
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    if actual != expected {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
            name,
            expected,
            actual,
        });
    }
    Ok(())
}

fn protected_payload_aad<'a>(
    context: ProtectedPayloadContext<'a>,
    protected_body: &[u8],
) -> Result<&'a [u8], Ikev2ProtectedPayloadCryptoError> {
    let payload_header_offset = HEADER_LEN
        .checked_add(context.payload_offset)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let protected_body_offset = payload_header_offset
        .checked_add(GENERIC_PAYLOAD_HEADER_LEN)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let protected_body_end = protected_body_offset
        .checked_add(protected_body.len())
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;

    if protected_body_end > context.message_bytes.len() {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    }
    if context
        .message_bytes
        .get(protected_body_offset..protected_body_end)
        != Some(protected_body)
    {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    }

    context
        .message_bytes
        .get(..protected_body_offset)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)
}

fn decrypt_aes_gcm(
    encryption: Ikev2EncryptionAlgorithm,
    keys: SelectedProtectedPayloadKeys<'_>,
    aad: &[u8],
    protected_body: &[u8],
) -> Result<Vec<u8>, Ikev2ProtectedPayloadCryptoError> {
    let min_len = AES_GCM_EXPLICIT_IV_LEN + AES_GCM_ICV_LEN;
    if protected_body.len() < min_len {
        return Err(Ikev2ProtectedPayloadCryptoError::ProtectedPayloadTooShort {
            min_len,
            actual: protected_body.len(),
        });
    }

    let (explicit_iv, ciphertext_and_tag) = protected_body.split_at(AES_GCM_EXPLICIT_IV_LEN);
    let mut nonce = [0_u8; AES_GCM_SALT_LEN + AES_GCM_EXPLICIT_IV_LEN];
    nonce[..AES_GCM_SALT_LEN].copy_from_slice(keys.salt);
    nonce[AES_GCM_SALT_LEN..].copy_from_slice(explicit_iv);

    let payload = Payload {
        msg: ciphertext_and_tag,
        aad,
    };
    match encryption {
        Ikev2EncryptionAlgorithm::AesGcm16_128 => {
            validate_key_len(
                "AES-GCM-128 key",
                AES_128_KEY_LEN,
                keys.encryption_key.len(),
            )?;
            let key = <&Key<Aes128Gcm>>::try_from(keys.encryption_key).map_err(|_| {
                Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                    name: "AES-GCM-128 key",
                    expected: AES_128_KEY_LEN,
                    actual: keys.encryption_key.len(),
                }
            })?;
            let nonce = <&Nonce<Aes128Gcm>>::try_from(nonce.as_slice())
                .map_err(|_| Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
            let cipher = Aes128Gcm::new(key);
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| Ikev2ProtectedPayloadCryptoError::AuthenticationFailed)
        }
        Ikev2EncryptionAlgorithm::AesGcm16_256 => {
            validate_key_len(
                "AES-GCM-256 key",
                AES_256_KEY_LEN,
                keys.encryption_key.len(),
            )?;
            let key = <&Key<Aes256Gcm>>::try_from(keys.encryption_key).map_err(|_| {
                Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                    name: "AES-GCM-256 key",
                    expected: AES_256_KEY_LEN,
                    actual: keys.encryption_key.len(),
                }
            })?;
            let nonce = <&Nonce<Aes256Gcm>>::try_from(nonce.as_slice())
                .map_err(|_| Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
            let cipher = Aes256Gcm::new(key);
            cipher
                .decrypt(nonce, payload)
                .map_err(|_| Ikev2ProtectedPayloadCryptoError::AuthenticationFailed)
        }
    }
}

fn strip_ike_padding(plaintext: Vec<u8>) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
    let Some((&pad_len, body_with_padding)) = plaintext.split_last() else {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidPadding {
            plaintext_len: 0,
            pad_len: 0,
        });
    };
    let pad_len = usize::from(pad_len);
    if pad_len > body_with_padding.len() {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidPadding {
            plaintext_len: plaintext.len(),
            pad_len,
        });
    }
    let cleartext_len = body_with_padding.len() - pad_len;
    Ok(Bytes::copy_from_slice(&body_with_padding[..cleartext_len]))
}
