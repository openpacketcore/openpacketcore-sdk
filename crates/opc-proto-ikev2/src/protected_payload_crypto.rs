//! IKEv2 protected-payload decryption and sealing helpers for SA_INIT-derived keys.
//!
//! @spec IETF RFC4868 2.1-2.7; IETF RFC5282 3; IETF RFC7296 3.14;
//! IETF RFC7383 2.5
//! @req REQ-IETF-RFC5282-AES-GCM-PROTECTED-PAYLOAD-001
//! @req REQ-IETF-RFC7296-AES-CBC-ETM-PROTECTED-PAYLOAD-001

use std::{error::Error, fmt};

use aes::{cipher::consts::U12, Aes128, Aes192, Aes256};
use aes_gcm::{
    aead::{Aead, Key, KeyInit, Nonce, Payload},
    Aes128Gcm, Aes256Gcm, AesGcm,
};
use bytes::Bytes;
use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use opc_crypto_provider::CryptoOperationErrorCode;
use rand::TryCryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    crypto::{
        CryptoProvider, ProtectedPayloadContext, ProtectedPayloadKind, ProtectedPayloadOpenError,
    },
    crypto_module::{
        execute_aead_open, execute_aead_seal, execute_cbc_decrypt, execute_cbc_encrypt,
        execute_integrity_checksum, execute_integrity_verification, with_entropy_operation,
        Ikev2CryptoModuleError,
    },
    fragmentation::IKEV2_ENCRYPTED_FRAGMENT_FIXED_BODY_LEN,
    hmac_sha2::{hmac_sha2_256, hmac_sha2_384, hmac_sha2_512},
    payload::GENERIC_PAYLOAD_HEADER_LEN,
    sa_init_crypto::{
        Ikev2EncryptionAlgorithm, Ikev2IntegrityAlgorithm, Ikev2SaInitCryptoProfile,
        Ikev2SaInitKeyMaterial,
    },
    HEADER_LEN,
};

const AES_GCM_SALT_LEN: usize = 4;
const AES_GCM_EXPLICIT_IV_LEN: usize = 8;
const AES_GCM_ICV_LEN: usize = 16;
const AES_CBC_IV_LEN: usize = 16;
const AES_CBC_BLOCK_LEN: usize = 16;
const AES_128_KEY_LEN: usize = 16;
const AES_192_KEY_LEN: usize = 24;
const AES_256_KEY_LEN: usize = 32;
const IKE_HEADER_LENGTH_OFFSET: usize = 24;
const GENERIC_PAYLOAD_LENGTH_OFFSET: usize = 2;

type Aes192Gcm = AesGcm<Aes192, U12>;

/// RFC 5282 AES-GCM explicit IV length used in IKEv2 `SK` payload bodies.
pub const IKEV2_AES_GCM_EXPLICIT_IV_LEN: usize = AES_GCM_EXPLICIT_IV_LEN;

/// RFC 7296 AES-CBC IV and block length used in IKEv2 `SK`/`SKF` payloads.
pub const IKEV2_AES_CBC_IV_LEN: usize = AES_CBC_IV_LEN;

/// Returns the sealed AES-GCM protected body length for a cleartext chain.
///
/// The returned length is the `SK` body length:
/// explicit IV || ciphertext(cleartext || zero padding || pad-length octet) ||
/// authentication tag. It does not include the IKEv2 generic payload header.
pub const fn ikev2_aes_gcm_protected_body_len(
    cleartext_payloads_len: usize,
    padding_len: u8,
) -> Option<usize> {
    let with_padding = match cleartext_payloads_len.checked_add(padding_len as usize) {
        Some(value) => value,
        None => return None,
    };
    let plaintext_len = match with_padding.checked_add(1) {
        Some(value) => value,
        None => return None,
    };
    let with_iv = match AES_GCM_EXPLICIT_IV_LEN.checked_add(plaintext_len) {
        Some(value) => value,
        None => return None,
    };
    with_iv.checked_add(AES_GCM_ICV_LEN)
}

/// Returns the IKEv2 generic `SK` payload length field value for AES-GCM.
///
/// This includes the 4-octet generic payload header plus the protected body
/// length returned by [`ikev2_aes_gcm_protected_body_len`].
pub const fn ikev2_aes_gcm_protected_payload_len(
    cleartext_payloads_len: usize,
    padding_len: u8,
) -> Option<usize> {
    let body_len = match ikev2_aes_gcm_protected_body_len(cleartext_payloads_len, padding_len) {
        Some(value) => value,
        None => return None,
    };
    GENERIC_PAYLOAD_HEADER_LEN.checked_add(body_len)
}

/// Return the minimal RFC 7296 padding length that block-aligns AES-CBC data.
///
/// The encrypted plaintext is `cleartext || padding || Pad Length`. IKE padding
/// octets are deliberately not interpreted; only the final Pad Length octet is
/// structural. This helper chooses the shortest valid all-zero padding used by
/// the production sealing helpers.
pub const fn ikev2_aes_cbc_padding_len(cleartext_payloads_len: usize) -> Option<u8> {
    let with_pad_length = match cleartext_payloads_len.checked_add(1) {
        Some(value) => value,
        None => return None,
    };
    let remainder = with_pad_length % AES_CBC_BLOCK_LEN;
    let padding_len = if remainder == 0 {
        0
    } else {
        AES_CBC_BLOCK_LEN - remainder
    };
    Some(padding_len as u8)
}

/// Return the AES-CBC protected crypto-body length for an executable profile.
///
/// The returned length is `IV || ciphertext || ICV`. For `SKF`, the four-octet
/// Fragment Number/Total Fragments prefix is outside this length and must be
/// included in [`ProtectedPayloadSealContext::message_prefix`].
pub fn ikev2_aes_cbc_protected_body_len(
    profile: Ikev2SaInitCryptoProfile,
    cleartext_payloads_len: usize,
) -> Option<usize> {
    if profile.encryption().is_aead() || profile.integrity().is_none() {
        return None;
    }
    let padding_len = usize::from(ikev2_aes_cbc_padding_len(cleartext_payloads_len)?);
    let ciphertext_len = cleartext_payloads_len
        .checked_add(padding_len)?
        .checked_add(1)?;
    AES_CBC_IV_LEN
        .checked_add(ciphertext_len)?
        .checked_add(profile.integrity_icv_len())
}

/// Return the generic IKEv2 `SK`/`SKF` payload length field for AES-CBC.
///
/// `SKF` callers pass [`IKEV2_ENCRYPTED_FRAGMENT_FIXED_BODY_LEN`] as
/// `unprotected_body_prefix_len`; ordinary `SK` callers pass zero.
pub fn ikev2_aes_cbc_protected_payload_len(
    profile: Ikev2SaInitCryptoProfile,
    cleartext_payloads_len: usize,
    unprotected_body_prefix_len: usize,
) -> Option<usize> {
    GENERIC_PAYLOAD_HEADER_LEN
        .checked_add(unprotected_body_prefix_len)?
        .checked_add(ikev2_aes_cbc_protected_body_len(
            profile,
            cleartext_payloads_len,
        )?)
}

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

/// Monotonic RFC 5282 AES-GCM explicit-IV allocator for one sending direction.
///
/// The value returned by [`Self::next_value`] is the next outbound explicit IV
/// counter value to persist with the IKE SA. Restoring a counter with that value
/// resumes sending strictly after the last successfully allocated IV and avoids
/// nonce reuse with the same `SK_e*` key and salt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2AesGcmExplicitIvCounter {
    next_value: u64,
}

impl Ikev2AesGcmExplicitIvCounter {
    /// Build a counter from the next explicit IV value to send.
    ///
    /// Pass `0` for a fresh direction, or the persisted [`Self::next_value`]
    /// from sealed IKE SA state when adopting an established SA.
    pub const fn new(next_value: u64) -> Self {
        Self { next_value }
    }

    /// Next explicit IV counter value to persist for restore.
    pub const fn next_value(self) -> u64 {
        self.next_value
    }

    /// Allocate the next AES-GCM explicit IV in network byte order.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2ProtectedPayloadCryptoError::ExplicitIvExhausted`] when
    /// the counter has reached its fail-closed wrap guard. Rekey the IKE SA
    /// before sending more protected messages under this direction key.
    pub fn next_explicit_iv(
        &mut self,
    ) -> Result<[u8; IKEV2_AES_GCM_EXPLICIT_IV_LEN], Ikev2ProtectedPayloadCryptoError> {
        if self.next_value == u64::MAX {
            return Err(Ikev2ProtectedPayloadCryptoError::ExplicitIvExhausted);
        }
        let explicit_iv = self.next_value.to_be_bytes();
        self.next_value += 1;
        Ok(explicit_iv)
    }
}

impl Default for Ikev2AesGcmExplicitIvCounter {
    fn default() -> Self {
        Self::new(0)
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
    /// An explicit IV has the wrong wire length.
    InvalidIvLength,
    /// AES-CBC ciphertext is empty or not block aligned.
    InvalidCiphertextLength,
    /// The protected payload offset or length is inconsistent with the message.
    InvalidAssociatedData,
    /// Protected-payload authentication failed.
    AuthenticationFailed,
    /// Decrypted IKE padding is structurally invalid.
    InvalidPadding,
    /// AES-GCM explicit IV counter cannot allocate without wrapping.
    ExplicitIvExhausted,
    /// The selected secure entropy source could not produce a fresh AES-CBC IV.
    RandomIvGenerationFailed,
    /// The admitted process crypto module was absent, withdrawn, or failed.
    CryptoModuleFailure,
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
            Self::InvalidIvLength => "ike_protected_payload_crypto_invalid_iv_length",
            Self::InvalidCiphertextLength => {
                "ike_protected_payload_crypto_invalid_ciphertext_length"
            }
            Self::InvalidAssociatedData => "ike_protected_payload_crypto_invalid_aad",
            Self::AuthenticationFailed => "ike_protected_payload_crypto_authentication_failed",
            Self::InvalidPadding => "ike_protected_payload_crypto_invalid_padding",
            Self::ExplicitIvExhausted => "ike_protected_payload_crypto_explicit_iv_exhausted",
            Self::RandomIvGenerationFailed => {
                "ike_protected_payload_crypto_random_iv_generation_failed"
            }
            Self::CryptoModuleFailure => "ike_protected_payload_crypto_module_failure",
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
        /// Negotiated integrity algorithm, if any.
        integrity: Option<Ikev2IntegrityAlgorithm>,
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
    /// An explicit IV was truncated or had the wrong wire length.
    InvalidIvLength {
        /// Required IV length in octets.
        expected: usize,
        /// Actual available IV length in octets.
        actual: usize,
    },
    /// AES-CBC ciphertext was empty or not block aligned.
    InvalidCiphertextLength {
        /// Required AES block length in octets.
        block_len: usize,
        /// Actual ciphertext length in octets.
        actual: usize,
    },
    /// Protected payload associated-data inputs were inconsistent.
    InvalidAssociatedData,
    /// Protected-payload authentication failed.
    AuthenticationFailed,
    /// IKE padding was structurally invalid after authenticated decryption.
    InvalidPadding {
        /// Decrypted plaintext length in octets.
        plaintext_len: usize,
        /// Pad length octet value.
        pad_len: usize,
    },
    /// AES-GCM explicit IV counter is exhausted.
    ExplicitIvExhausted,
    /// The secure random source failed to generate an AES-CBC IV.
    RandomIvGenerationFailed,
    /// The admitted process crypto module was absent, withdrawn, or failed.
    CryptoModuleFailure {
        /// Stable, redaction-safe module boundary error.
        error: Ikev2CryptoModuleError,
    },
}

/// Exact authentication context for sealing one IKEv2 protected payload body.
///
/// `message_prefix` must be the final outer IKE message bytes from the IKE
/// header through the protected payload generic header, excluding only the
/// protected body that this helper returns. For an `SK` payload with no
/// cleartext prefix, that is the 28-byte IKE header plus the 4-byte `SK`
/// generic payload header. If there are unencrypted payloads before `SK`, they
/// must be included too. For `SKF`, it also includes the four-byte unencrypted
/// fragment prefix after the generic header. AES-GCM authenticates this prefix
/// as AAD; AES-CBC/HMAC authenticates the exact complete prefix and ciphertext
/// before appending the ICV. The outer IKE and generic payload Length fields
/// must already contain their final values. Full message construction and
/// retransmission caching remain with the caller.
#[derive(Clone, Copy)]
pub struct ProtectedPayloadSealContext<'a> {
    /// Protected payload kind to seal (`SK` or `SKF`).
    pub kind: ProtectedPayloadKind,
    /// Exact outer message prefix authenticated as AEAD AAD or HMAC input.
    pub message_prefix: &'a [u8],
}

impl fmt::Debug for ProtectedPayloadSealContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedPayloadSealContext")
            .field("kind", &self.kind)
            .field("message_prefix_len", &self.message_prefix.len())
            .finish()
    }
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
            Self::InvalidIvLength { .. } => Ikev2ProtectedPayloadCryptoErrorCode::InvalidIvLength,
            Self::InvalidCiphertextLength { .. } => {
                Ikev2ProtectedPayloadCryptoErrorCode::InvalidCiphertextLength
            }
            Self::InvalidAssociatedData => {
                Ikev2ProtectedPayloadCryptoErrorCode::InvalidAssociatedData
            }
            Self::AuthenticationFailed => {
                Ikev2ProtectedPayloadCryptoErrorCode::AuthenticationFailed
            }
            Self::InvalidPadding { .. } => Ikev2ProtectedPayloadCryptoErrorCode::InvalidPadding,
            Self::ExplicitIvExhausted => Ikev2ProtectedPayloadCryptoErrorCode::ExplicitIvExhausted,
            Self::RandomIvGenerationFailed => {
                Ikev2ProtectedPayloadCryptoErrorCode::RandomIvGenerationFailed
            }
            Self::CryptoModuleFailure { .. } => {
                Ikev2ProtectedPayloadCryptoErrorCode::CryptoModuleFailure
            }
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
                integrity,
            } => {
                write!(
                    f,
                    "unsupported IKEv2 protected payload profile {} with integrity {}",
                    encryption.name(),
                    integrity.map_or("none", Ikev2IntegrityAlgorithm::name)
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
            Self::InvalidIvLength { expected, actual } => {
                write!(
                    f,
                    "invalid IKEv2 protected payload IV length: expected {expected}, actual {actual}"
                )
            }
            Self::InvalidCiphertextLength { block_len, actual } => {
                write!(
                    f,
                    "invalid IKEv2 protected payload ciphertext length: block {block_len}, actual {actual}"
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
            Self::ExplicitIvExhausted => f.write_str("IKEv2 AES-GCM explicit IV counter exhausted"),
            Self::RandomIvGenerationFailed => {
                f.write_str("IKEv2 AES-CBC secure IV generation failed")
            }
            Self::CryptoModuleFailure { error } => {
                write!(f, "IKEv2 crypto module operation failed: {error}")
            }
        }
    }
}

impl Error for Ikev2ProtectedPayloadCryptoError {}

/// Typed error returned when the concrete SA_INIT-key provider fails while
/// [`crate::open_protected_payloads`] is opening an `SK` or `SKF` payload.
///
/// The outer error retains uniform provider-rejection classification through
/// [`ProtectedPayloadOpenError::as_str`]. Its
/// [`crate::ProtectedPayloadOpenFailure::provider_error`] preserves the exact
/// [`Ikev2ProtectedPayloadCryptoError`] for local diagnostics and stable code
/// mapping.
pub type Ikev2ProtectedPayloadOpenError =
    ProtectedPayloadOpenError<Ikev2ProtectedPayloadCryptoError>;

/// Concrete [`CryptoProvider`] for executable IKEv2 `SK` and `SKF` profiles.
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

/// Authenticate and decrypt one IKEv2 `SK` or `SKF` payload body with SA_INIT keys.
///
/// The helper supports RFC 5282 `ENCR_AES_GCM_16` and RFC 7296 AES-CBC with a
/// typed SHA-2 integrity transform. It uses `SK_ei`/`SK_ai` for
/// [`Ikev2ProtectedPayloadDirection::InitiatorToResponder`] and
/// `SK_er`/`SK_ar` for
/// [`Ikev2ProtectedPayloadDirection::ResponderToInitiator`].
///
/// # Errors
///
/// Returns [`Ikev2ProtectedPayloadCryptoError`] when the profile, keys, body,
/// associated data, authentication, ciphertext shape, or authenticated IKE
/// padding is invalid. Encrypt-then-MAC profiles verify the ICV in constant
/// time before decrypting.
pub fn decrypt_ikev2_sa_init_protected_payload(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    context: ProtectedPayloadContext<'_>,
    protected_body: &[u8],
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
    validate_profile(profile)?;

    let keys = select_keys(profile, key_material, direction)?;
    let view = protected_payload_view(context, protected_body)?;
    let plaintext = if profile.encryption().is_aead() {
        Zeroizing::new(decrypt_aes_gcm(
            profile.encryption(),
            keys,
            view.authenticated_prefix,
            view.crypto_body,
        )?)
    } else {
        let integrity = profile.integrity().ok_or(
            Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile {
                encryption: profile.encryption(),
                integrity: None,
            },
        )?;
        decrypt_aes_cbc(
            profile.encryption(),
            integrity,
            keys,
            context.message_bytes,
            view,
        )?
    };
    strip_ike_padding(plaintext)
}

/// Authenticate and encrypt one AES-GCM IKEv2 `SK`/`SKF` crypto body.
///
/// The returned bytes are the protected payload body:
/// explicit IV || ciphertext || authentication tag. The caller remains
/// responsible for constructing the final outer IKE header and payload header
/// whose exact bytes are supplied in [`ProtectedPayloadSealContext`]. For
/// `SKF`, the context prefix also includes Fragment Number and Total Fragments,
/// and the returned bytes are the `encrypted_fragment` passed to the structural
/// SKF builder.
///
/// `cleartext_payloads` is the complete inner cleartext payload chain beginning
/// with the payload type named by the outer `SK` generic header. This helper
/// appends `padding_len` zero padding octets plus the required IKE Pad Length
/// octet before encryption.
///
/// # Errors
///
/// Returns [`Ikev2ProtectedPayloadCryptoError`] when the profile, keys, payload
/// kind, or AAD prefix is invalid for sealing.
///
/// # Security
///
/// `explicit_iv` is the AES-GCM explicit nonce field from RFC 5282 section 4.
/// Callers must ensure it is never reused with the same direction key and salt.
/// Reusing an AES-GCM nonce under one IKE SA can disclose plaintext relations
/// and permit tag forgery. Production callers should allocate this value from a
/// monotonic per-direction counter stored with the IKE SA state.
pub fn seal_ikev2_sa_init_protected_payload(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    context: ProtectedPayloadSealContext<'_>,
    cleartext_payloads: &[u8],
    padding_len: u8,
    explicit_iv: [u8; IKEV2_AES_GCM_EXPLICIT_IV_LEN],
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
    let keys = select_seal_keys(profile, key_material, direction)?;
    let plaintext = padded_ike_plaintext(cleartext_payloads, padding_len)?;
    let sealed = encrypt_aes_gcm(
        profile.encryption(),
        keys,
        context.message_prefix,
        &plaintext,
        explicit_iv,
    )?;
    validate_seal_context(context, sealed.len())?;
    Ok(Bytes::from(sealed))
}

/// Authenticate and encrypt one IKEv2 `SK` payload body using a monotonic IV counter.
///
/// This is the stateful counterpart to
/// [`seal_ikev2_sa_init_protected_payload`]. Persist [`Ikev2AesGcmExplicitIvCounter::next_value`]
/// with the sealed IKE SA state after each successful call, and restore the
/// counter with that value before an HA adopter sends more protected messages.
///
/// # Errors
///
/// Returns [`Ikev2ProtectedPayloadCryptoError`] when the profile, keys, payload
/// kind, AAD prefix, or IV counter state is invalid.
pub fn seal_ikev2_sa_init_protected_payload_with_iv_counter(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    context: ProtectedPayloadSealContext<'_>,
    cleartext_payloads: &[u8],
    padding_len: u8,
    iv_counter: &mut Ikev2AesGcmExplicitIvCounter,
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
    let keys = select_seal_keys(profile, key_material, direction)?;
    let explicit_iv = iv_counter.next_explicit_iv()?;
    let plaintext = padded_ike_plaintext(cleartext_payloads, padding_len)?;
    let sealed = encrypt_aes_gcm(
        profile.encryption(),
        keys,
        context.message_prefix,
        &plaintext,
        explicit_iv,
    )?;
    validate_seal_context(context, sealed.len())?;
    Ok(Bytes::from(sealed))
}

/// Seal one AES-CBC/HMAC IKEv2 `SK`/`SKF` crypto body with a fresh random IV.
///
/// This is the production-safe AES-CBC entry point. It always obtains a new
/// 16-octet IV from the admitted module's approved entropy operation, applies
/// the shortest block-aligning RFC 7296 IKE padding, encrypts with the
/// directional `SK_e*`, and authenticates the final message prefix plus IV and
/// ciphertext with directional `SK_a*`.
///
/// The caller must construct final IKE and generic payload length fields before
/// calling. Use [`ikev2_aes_cbc_protected_body_len`] or
/// [`ikev2_aes_cbc_protected_payload_len`] to calculate them. For `SKF`,
/// `message_prefix` must end after Fragment Number/Total Fragments and the
/// returned bytes are the encrypted-fragment portion only.
///
/// # Errors
///
/// Returns [`Ikev2ProtectedPayloadCryptoError`] when the profile, key material,
/// final length fields, fragment prefix, padding length, encryption, integrity,
/// or admitted secure entropy source is invalid.
pub fn seal_ikev2_sa_init_aes_cbc_protected_payload(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    context: ProtectedPayloadSealContext<'_>,
    cleartext_payloads: &[u8],
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
    let mut iv = [0_u8; IKEV2_AES_CBC_IV_LEN];
    with_entropy_operation(|module| module.fill_random(&mut iv)).map_err(|error| {
        if error.operation_code() == Some(CryptoOperationErrorCode::EntropyUnavailable) {
            Ikev2ProtectedPayloadCryptoError::RandomIvGenerationFailed
        } else {
            map_crypto_module_error(error)
        }
    })?;
    seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector(
        profile,
        key_material,
        direction,
        context,
        cleartext_payloads,
        iv,
    )
}

/// Seal one AES-CBC/HMAC IKEv2 `SK`/`SKF` body with caller-owned entropy.
///
/// The [`TryCryptoRng`] bound requires a cryptographic RNG implementation. The
/// caller must still seed it unpredictably and must never use a fixed-seed RNG
/// in production. This compatibility boundary does not prove that IV entropy
/// came from the process's admitted module; validated deployments should use
/// [`seal_ikev2_sa_init_aes_cbc_protected_payload`]. AES-CBC and integrity
/// operations still route through the admitted module. The generated IV is
/// never logged or exposed separately from the protected wire body.
///
/// # Errors
///
/// Returns [`Ikev2ProtectedPayloadCryptoError`] under the same conditions as
/// [`seal_ikev2_sa_init_aes_cbc_protected_payload`].
pub fn seal_ikev2_sa_init_aes_cbc_protected_payload_with_rng<R>(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    context: ProtectedPayloadSealContext<'_>,
    cleartext_payloads: &[u8],
    rng: &mut R,
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError>
where
    R: TryCryptoRng + ?Sized,
{
    let mut iv = [0_u8; IKEV2_AES_CBC_IV_LEN];
    rng.try_fill_bytes(&mut iv)
        .map_err(|_| Ikev2ProtectedPayloadCryptoError::RandomIvGenerationFailed)?;
    seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector(
        profile,
        key_material,
        direction,
        context,
        cleartext_payloads,
        iv,
    )
}

/// Deterministically seal an AES-CBC/HMAC `SK`/`SKF` body for test vectors.
///
/// # Security
///
/// This is a low-level interoperability/vector boundary. Production code in a
/// validated deployment must use
/// [`seal_ikev2_sa_init_aes_cbc_protected_payload`]. Reusing or predicting an
/// IV with the same directional key violates the IKEv2 AES-CBC security
/// contract.
///
/// # Errors
///
/// Returns [`Ikev2ProtectedPayloadCryptoError`] when the profile, keys, final
/// length fields, fragment prefix, encryption, or integrity operation is invalid.
pub fn seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    context: ProtectedPayloadSealContext<'_>,
    cleartext_payloads: &[u8],
    iv: [u8; IKEV2_AES_CBC_IV_LEN],
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
    validate_profile(profile)?;
    let integrity = profile.integrity().ok_or(
        Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile {
            encryption: profile.encryption(),
            integrity: None,
        },
    )?;
    if profile.encryption().is_aead() {
        return Err(
            Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile {
                encryption: profile.encryption(),
                integrity: profile.integrity(),
            },
        );
    }
    let keys = select_seal_keys(profile, key_material, direction)?;
    let padding_len = ikev2_aes_cbc_padding_len(cleartext_payloads.len()).ok_or(
        Ikev2ProtectedPayloadCryptoError::InvalidPadding {
            plaintext_len: cleartext_payloads.len(),
            pad_len: 0,
        },
    )?;
    let mut plaintext = padded_ike_plaintext(cleartext_payloads, padding_len)?;
    encrypt_aes_cbc(
        profile.encryption(),
        keys.encryption_key,
        &iv,
        &mut plaintext,
    )?;

    let icv_len = profile.integrity_icv_len();
    let final_body_len = AES_CBC_IV_LEN
        .checked_add(plaintext.len())
        .and_then(|value| value.checked_add(icv_len))
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    validate_seal_context(context, final_body_len)?;

    let mut protected_body = Vec::with_capacity(final_body_len);
    protected_body.extend_from_slice(&iv);
    protected_body.extend_from_slice(&plaintext);
    let icv = compute_integrity_checksum(
        integrity,
        keys.integrity_key,
        context.message_prefix,
        &protected_body,
    )?;
    protected_body.extend_from_slice(&icv);
    Ok(Bytes::from(protected_body))
}

#[derive(Clone, Copy)]
pub(crate) struct SelectedProtectedPayloadKeys<'a> {
    pub(crate) encryption_key: &'a [u8],
    pub(crate) salt: &'a [u8],
    pub(crate) integrity_key: &'a [u8],
}

fn validate_profile(
    profile: Ikev2SaInitCryptoProfile,
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    match (profile.encryption().is_aead(), profile.integrity()) {
        (true, None) | (false, Some(_)) => Ok(()),
        _ => Err(
            Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile {
                encryption: profile.encryption(),
                integrity: profile.integrity(),
            },
        ),
    }
}

fn select_seal_keys<'a>(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &'a Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
) -> Result<SelectedProtectedPayloadKeys<'a>, Ikev2ProtectedPayloadCryptoError> {
    validate_profile(profile)?;
    select_keys(profile, key_material, direction)
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
    let (encryption_key, salt) = if profile.encryption().is_aead() {
        let encryption_key_len = expected_sk_e_len.checked_sub(AES_GCM_SALT_LEN).ok_or(
            Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                name: direction.encryption_key_name(),
                expected: expected_sk_e_len,
                actual: sk_e.len(),
            },
        )?;
        sk_e.split_at(encryption_key_len)
    } else {
        (sk_e, &[][..])
    };

    Ok(SelectedProtectedPayloadKeys {
        encryption_key,
        salt,
        integrity_key: sk_a,
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

#[derive(Clone, Copy)]
struct ProtectedPayloadView<'a> {
    authenticated_prefix: &'a [u8],
    crypto_body: &'a [u8],
    crypto_body_message_offset: usize,
}

fn protected_payload_view<'a>(
    context: ProtectedPayloadContext<'a>,
    protected_body: &'a [u8],
) -> Result<ProtectedPayloadView<'a>, Ikev2ProtectedPayloadCryptoError> {
    let payload_header_offset = HEADER_LEN
        .checked_add(context.payload_offset)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let protected_body_offset = payload_header_offset
        .checked_add(GENERIC_PAYLOAD_HEADER_LEN)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let protected_body_end = protected_body_offset
        .checked_add(protected_body.len())
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;

    // RFC 7296 requires SK (and RFC 7383 SKF) to be the final payload. Enforce
    // exact coverage so integrity is never verified over a message suffix the
    // provider silently ignored.
    if protected_body_end != context.message_bytes.len() {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    }
    if context
        .message_bytes
        .get(protected_body_offset..protected_body_end)
        != Some(protected_body)
    {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    }

    let fixed_prefix_len = protected_body_prefix_len(context.kind);
    if protected_body.len() < fixed_prefix_len {
        return Err(Ikev2ProtectedPayloadCryptoError::ProtectedPayloadTooShort {
            min_len: fixed_prefix_len,
            actual: protected_body.len(),
        });
    }
    if context.kind == ProtectedPayloadKind::EncryptedFragment {
        validate_fragment_prefix(
            context.first_inner_payload == crate::payload::PayloadType::NoNext,
            &protected_body[..fixed_prefix_len],
        )?;
    }
    let crypto_body_message_offset = protected_body_offset
        .checked_add(fixed_prefix_len)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let authenticated_prefix = context
        .message_bytes
        .get(..crypto_body_message_offset)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let crypto_body = protected_body
        .get(fixed_prefix_len..)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;

    Ok(ProtectedPayloadView {
        authenticated_prefix,
        crypto_body,
        crypto_body_message_offset,
    })
}

const fn protected_body_prefix_len(kind: ProtectedPayloadKind) -> usize {
    match kind {
        ProtectedPayloadKind::Encrypted => 0,
        ProtectedPayloadKind::EncryptedFragment => IKEV2_ENCRYPTED_FRAGMENT_FIXED_BODY_LEN,
    }
}

fn validate_fragment_prefix(
    first_inner_payload_is_none: bool,
    prefix: &[u8],
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    let [fragment_number_hi, fragment_number_lo, total_hi, total_lo] = prefix else {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    };
    let fragment_number = u16::from_be_bytes([*fragment_number_hi, *fragment_number_lo]);
    let total_fragments = u16::from_be_bytes([*total_hi, *total_lo]);
    if fragment_number == 0
        || total_fragments == 0
        || fragment_number > total_fragments
        || (fragment_number > 1 && !first_inner_payload_is_none)
    {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    }
    Ok(())
}

fn validate_seal_context(
    context: ProtectedPayloadSealContext<'_>,
    crypto_body_len: usize,
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    let fixed_prefix_len = protected_body_prefix_len(context.kind);
    let minimum_prefix_len = HEADER_LEN
        .checked_add(GENERIC_PAYLOAD_HEADER_LEN)
        .and_then(|value| value.checked_add(fixed_prefix_len))
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    if context.message_prefix.len() < minimum_prefix_len {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    }

    let generic_header_offset = context
        .message_prefix
        .len()
        .checked_sub(fixed_prefix_len + GENERIC_PAYLOAD_HEADER_LEN)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let generic_header = context
        .message_prefix
        .get(generic_header_offset..generic_header_offset + GENERIC_PAYLOAD_HEADER_LEN)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let payload_length_bytes = generic_header
        .get(GENERIC_PAYLOAD_LENGTH_OFFSET..GENERIC_PAYLOAD_LENGTH_OFFSET + 2)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let [payload_length_hi, payload_length_lo] = payload_length_bytes else {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    };
    let declared_payload_len = u16::from_be_bytes([*payload_length_hi, *payload_length_lo]);
    let expected_payload_len = GENERIC_PAYLOAD_HEADER_LEN
        .checked_add(fixed_prefix_len)
        .and_then(|value| value.checked_add(crypto_body_len))
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    if usize::from(declared_payload_len) != expected_payload_len {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    }

    if context.kind == ProtectedPayloadKind::EncryptedFragment {
        let fragment_prefix = context
            .message_prefix
            .get(context.message_prefix.len() - fixed_prefix_len..)
            .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
        validate_fragment_prefix(generic_header[0] == 0, fragment_prefix)?;
    }

    let ike_length_bytes = context
        .message_prefix
        .get(IKE_HEADER_LENGTH_OFFSET..IKE_HEADER_LENGTH_OFFSET + 4)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let [length_0, length_1, length_2, length_3] = ike_length_bytes else {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    };
    let declared_ike_len = u32::from_be_bytes([*length_0, *length_1, *length_2, *length_3]);
    let expected_ike_len = context
        .message_prefix
        .len()
        .checked_add(crypto_body_len)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    if usize::try_from(declared_ike_len).ok() != Some(expected_ike_len) {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    }
    Ok(())
}

pub(crate) fn decrypt_aes_gcm(
    encryption: Ikev2EncryptionAlgorithm,
    keys: SelectedProtectedPayloadKeys<'_>,
    aad: &[u8],
    protected_body: &[u8],
) -> Result<Vec<u8>, Ikev2ProtectedPayloadCryptoError> {
    // Preserve the public protocol-boundary validation and stable error shape
    // before delegating to a provider. Providers may use a coarser invalid
    // input error, but callers must still receive the RFC-shaped minimum.
    let min_len = AES_GCM_EXPLICIT_IV_LEN + AES_GCM_ICV_LEN;
    if protected_body.len() < min_len {
        return Err(Ikev2ProtectedPayloadCryptoError::ProtectedPayloadTooShort {
            min_len,
            actual: protected_body.len(),
        });
    }
    execute_aead_open(
        encryption,
        keys.encryption_key,
        keys.salt,
        aad,
        protected_body,
    )
    .map(|plaintext| plaintext.to_vec())
    .map_err(map_crypto_module_error)
}

pub(crate) fn software_decrypt_aes_gcm(
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
    let mut nonce = Zeroizing::new([0_u8; AES_GCM_SALT_LEN + AES_GCM_EXPLICIT_IV_LEN]);
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
        Ikev2EncryptionAlgorithm::AesGcm16_192 => {
            validate_key_len(
                "AES-GCM-192 key",
                AES_192_KEY_LEN,
                keys.encryption_key.len(),
            )?;
            let key = <&Key<Aes192Gcm>>::try_from(keys.encryption_key).map_err(|_| {
                Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                    name: "AES-GCM-192 key",
                    expected: AES_192_KEY_LEN,
                    actual: keys.encryption_key.len(),
                }
            })?;
            let nonce = <&Nonce<Aes192Gcm>>::try_from(nonce.as_slice())
                .map_err(|_| Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
            Aes192Gcm::new(key)
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
        unsupported => Err(
            Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile {
                encryption: unsupported,
                integrity: None,
            },
        ),
    }
}

pub(crate) fn encrypt_aes_gcm(
    encryption: Ikev2EncryptionAlgorithm,
    keys: SelectedProtectedPayloadKeys<'_>,
    aad: &[u8],
    plaintext: &[u8],
    explicit_iv: [u8; IKEV2_AES_GCM_EXPLICIT_IV_LEN],
) -> Result<Vec<u8>, Ikev2ProtectedPayloadCryptoError> {
    execute_aead_seal(
        encryption,
        keys.encryption_key,
        keys.salt,
        &explicit_iv,
        aad,
        plaintext,
    )
    .map_err(map_crypto_module_error)
}

pub(crate) fn software_encrypt_aes_gcm(
    encryption: Ikev2EncryptionAlgorithm,
    keys: SelectedProtectedPayloadKeys<'_>,
    aad: &[u8],
    plaintext: &[u8],
    explicit_iv: [u8; IKEV2_AES_GCM_EXPLICIT_IV_LEN],
) -> Result<Vec<u8>, Ikev2ProtectedPayloadCryptoError> {
    let mut nonce = Zeroizing::new([0_u8; AES_GCM_SALT_LEN + AES_GCM_EXPLICIT_IV_LEN]);
    nonce[..AES_GCM_SALT_LEN].copy_from_slice(keys.salt);
    nonce[AES_GCM_SALT_LEN..].copy_from_slice(&explicit_iv);

    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext_and_tag = match encryption {
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
            Aes128Gcm::new(key)
                .encrypt(nonce, payload)
                .map_err(|_| Ikev2ProtectedPayloadCryptoError::AuthenticationFailed)?
        }
        Ikev2EncryptionAlgorithm::AesGcm16_192 => {
            validate_key_len(
                "AES-GCM-192 key",
                AES_192_KEY_LEN,
                keys.encryption_key.len(),
            )?;
            let key = <&Key<Aes192Gcm>>::try_from(keys.encryption_key).map_err(|_| {
                Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                    name: "AES-GCM-192 key",
                    expected: AES_192_KEY_LEN,
                    actual: keys.encryption_key.len(),
                }
            })?;
            let nonce = <&Nonce<Aes192Gcm>>::try_from(nonce.as_slice())
                .map_err(|_| Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
            Aes192Gcm::new(key)
                .encrypt(nonce, payload)
                .map_err(|_| Ikev2ProtectedPayloadCryptoError::AuthenticationFailed)?
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
            Aes256Gcm::new(key)
                .encrypt(nonce, payload)
                .map_err(|_| Ikev2ProtectedPayloadCryptoError::AuthenticationFailed)?
        }
        unsupported => {
            return Err(
                Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile {
                    encryption: unsupported,
                    integrity: None,
                },
            );
        }
    };

    let mut protected_body = Vec::with_capacity(AES_GCM_EXPLICIT_IV_LEN + ciphertext_and_tag.len());
    protected_body.extend_from_slice(&explicit_iv);
    protected_body.extend_from_slice(&ciphertext_and_tag);
    Ok(protected_body)
}

fn decrypt_aes_cbc(
    encryption: Ikev2EncryptionAlgorithm,
    integrity: Ikev2IntegrityAlgorithm,
    keys: SelectedProtectedPayloadKeys<'_>,
    message_bytes: &[u8],
    view: ProtectedPayloadView<'_>,
) -> Result<Zeroizing<Vec<u8>>, Ikev2ProtectedPayloadCryptoError> {
    let icv_len = integrity_icv_len(integrity);
    if view.crypto_body.len() < AES_CBC_IV_LEN {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidIvLength {
            expected: AES_CBC_IV_LEN,
            actual: view.crypto_body.len(),
        });
    }
    let min_len = AES_CBC_IV_LEN
        .checked_add(AES_CBC_BLOCK_LEN)
        .and_then(|value| value.checked_add(icv_len))
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    if view.crypto_body.len() < min_len {
        return Err(Ikev2ProtectedPayloadCryptoError::ProtectedPayloadTooShort {
            min_len,
            actual: view.crypto_body.len(),
        });
    }

    let (iv, ciphertext_and_icv) = view.crypto_body.split_at(AES_CBC_IV_LEN);
    let ciphertext_len = ciphertext_and_icv.len().checked_sub(icv_len).ok_or(
        Ikev2ProtectedPayloadCryptoError::ProtectedPayloadTooShort {
            min_len,
            actual: view.crypto_body.len(),
        },
    )?;
    if ciphertext_len == 0 || !ciphertext_len.is_multiple_of(AES_CBC_BLOCK_LEN) {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
            block_len: AES_CBC_BLOCK_LEN,
            actual: ciphertext_len,
        });
    }
    let (ciphertext, received_icv) = ciphertext_and_icv.split_at(ciphertext_len);

    let authenticated_end = view
        .crypto_body_message_offset
        .checked_add(AES_CBC_IV_LEN)
        .and_then(|value| value.checked_add(ciphertext_len))
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let authenticated_message = message_bytes
        .get(..authenticated_end)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    if authenticated_end
        .checked_add(icv_len)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?
        != message_bytes.len()
    {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData);
    }
    verify_integrity_checksum(
        integrity,
        keys.integrity_key,
        authenticated_message,
        received_icv,
    )?;

    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    decrypt_aes_cbc_in_place(encryption, keys.encryption_key, iv, &mut plaintext)?;
    Ok(plaintext)
}

pub(crate) fn encrypt_aes_cbc(
    encryption: Ikev2EncryptionAlgorithm,
    encryption_key: &[u8],
    iv: &[u8],
    plaintext: &mut [u8],
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    let ciphertext = execute_cbc_encrypt(encryption, encryption_key, iv, plaintext)
        .map_err(map_crypto_module_error)?;
    if ciphertext.len() != plaintext.len() {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
            block_len: AES_CBC_BLOCK_LEN,
            actual: ciphertext.len(),
        });
    }
    plaintext.copy_from_slice(&ciphertext);
    Ok(())
}

pub(crate) fn software_encrypt_aes_cbc(
    encryption: Ikev2EncryptionAlgorithm,
    encryption_key: &[u8],
    iv: &[u8],
    plaintext: &mut [u8],
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    if plaintext.is_empty() || !plaintext.len().is_multiple_of(AES_CBC_BLOCK_LEN) {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
            block_len: AES_CBC_BLOCK_LEN,
            actual: plaintext.len(),
        });
    }
    let plaintext_len = plaintext.len();
    match encryption {
        Ikev2EncryptionAlgorithm::AesCbc128 => {
            validate_key_len("AES-CBC-128 key", AES_128_KEY_LEN, encryption_key.len())?;
            let cipher =
                cbc::Encryptor::<Aes128>::new_from_slices(encryption_key, iv).map_err(|_| {
                    Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                        name: "AES-CBC-128 key or IV",
                        expected: AES_128_KEY_LEN,
                        actual: encryption_key.len(),
                    }
                })?;
            cipher
                .encrypt_padded::<NoPadding>(plaintext, plaintext_len)
                .map(|_| ())
                .map_err(
                    |_| Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
                        block_len: AES_CBC_BLOCK_LEN,
                        actual: plaintext_len,
                    },
                )
        }
        Ikev2EncryptionAlgorithm::AesCbc192 => {
            validate_key_len("AES-CBC-192 key", AES_192_KEY_LEN, encryption_key.len())?;
            let cipher =
                cbc::Encryptor::<Aes192>::new_from_slices(encryption_key, iv).map_err(|_| {
                    Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                        name: "AES-CBC-192 key or IV",
                        expected: AES_192_KEY_LEN,
                        actual: encryption_key.len(),
                    }
                })?;
            cipher
                .encrypt_padded::<NoPadding>(plaintext, plaintext_len)
                .map(|_| ())
                .map_err(
                    |_| Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
                        block_len: AES_CBC_BLOCK_LEN,
                        actual: plaintext_len,
                    },
                )
        }
        Ikev2EncryptionAlgorithm::AesCbc256 => {
            validate_key_len("AES-CBC-256 key", AES_256_KEY_LEN, encryption_key.len())?;
            let cipher =
                cbc::Encryptor::<Aes256>::new_from_slices(encryption_key, iv).map_err(|_| {
                    Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                        name: "AES-CBC-256 key or IV",
                        expected: AES_256_KEY_LEN,
                        actual: encryption_key.len(),
                    }
                })?;
            cipher
                .encrypt_padded::<NoPadding>(plaintext, plaintext_len)
                .map(|_| ())
                .map_err(
                    |_| Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
                        block_len: AES_CBC_BLOCK_LEN,
                        actual: plaintext_len,
                    },
                )
        }
        unsupported => Err(
            Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile {
                encryption: unsupported,
                integrity: None,
            },
        ),
    }
}

pub(crate) fn decrypt_aes_cbc_in_place(
    encryption: Ikev2EncryptionAlgorithm,
    encryption_key: &[u8],
    iv: &[u8],
    ciphertext: &mut [u8],
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    let plaintext = execute_cbc_decrypt(encryption, encryption_key, iv, ciphertext)
        .map_err(map_crypto_module_error)?;
    if plaintext.len() != ciphertext.len() {
        return Err(Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
            block_len: AES_CBC_BLOCK_LEN,
            actual: plaintext.len(),
        });
    }
    ciphertext.copy_from_slice(&plaintext);
    Ok(())
}

pub(crate) fn software_decrypt_aes_cbc_in_place(
    encryption: Ikev2EncryptionAlgorithm,
    encryption_key: &[u8],
    iv: &[u8],
    ciphertext: &mut [u8],
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    let ciphertext_len = ciphertext.len();
    match encryption {
        Ikev2EncryptionAlgorithm::AesCbc128 => {
            validate_key_len("AES-CBC-128 key", AES_128_KEY_LEN, encryption_key.len())?;
            let cipher =
                cbc::Decryptor::<Aes128>::new_from_slices(encryption_key, iv).map_err(|_| {
                    Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                        name: "AES-CBC-128 key or IV",
                        expected: AES_128_KEY_LEN,
                        actual: encryption_key.len(),
                    }
                })?;
            cipher
                .decrypt_padded::<NoPadding>(ciphertext)
                .map(|_| ())
                .map_err(
                    |_| Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
                        block_len: AES_CBC_BLOCK_LEN,
                        actual: ciphertext_len,
                    },
                )
        }
        Ikev2EncryptionAlgorithm::AesCbc192 => {
            validate_key_len("AES-CBC-192 key", AES_192_KEY_LEN, encryption_key.len())?;
            let cipher =
                cbc::Decryptor::<Aes192>::new_from_slices(encryption_key, iv).map_err(|_| {
                    Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                        name: "AES-CBC-192 key or IV",
                        expected: AES_192_KEY_LEN,
                        actual: encryption_key.len(),
                    }
                })?;
            cipher
                .decrypt_padded::<NoPadding>(ciphertext)
                .map(|_| ())
                .map_err(
                    |_| Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
                        block_len: AES_CBC_BLOCK_LEN,
                        actual: ciphertext_len,
                    },
                )
        }
        Ikev2EncryptionAlgorithm::AesCbc256 => {
            validate_key_len("AES-CBC-256 key", AES_256_KEY_LEN, encryption_key.len())?;
            let cipher =
                cbc::Decryptor::<Aes256>::new_from_slices(encryption_key, iv).map_err(|_| {
                    Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength {
                        name: "AES-CBC-256 key or IV",
                        expected: AES_256_KEY_LEN,
                        actual: encryption_key.len(),
                    }
                })?;
            cipher
                .decrypt_padded::<NoPadding>(ciphertext)
                .map(|_| ())
                .map_err(
                    |_| Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength {
                        block_len: AES_CBC_BLOCK_LEN,
                        actual: ciphertext_len,
                    },
                )
        }
        unsupported => Err(
            Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile {
                encryption: unsupported,
                integrity: None,
            },
        ),
    }
}

pub(crate) fn compute_integrity_checksum(
    integrity: Ikev2IntegrityAlgorithm,
    integrity_key: &[u8],
    first: &[u8],
    second: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2ProtectedPayloadCryptoError> {
    execute_integrity_checksum(integrity, integrity_key, first, second)
        .map_err(map_crypto_module_error)
}

pub(crate) fn software_compute_integrity_checksum(
    integrity: Ikev2IntegrityAlgorithm,
    integrity_key: &[u8],
    first: &[u8],
    second: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2ProtectedPayloadCryptoError> {
    validate_key_len("SK_a", integrity.key_len(), integrity_key.len())?;
    let mut checksum = match integrity {
        Ikev2IntegrityAlgorithm::HmacSha2_256_128 => hmac_sha2_256(integrity_key, &[first, second]),
        Ikev2IntegrityAlgorithm::HmacSha2_384_192 => hmac_sha2_384(integrity_key, &[first, second]),
        Ikev2IntegrityAlgorithm::HmacSha2_512_256 => hmac_sha2_512(integrity_key, &[first, second]),
    };
    checksum.truncate(integrity_icv_len(integrity));
    Ok(checksum)
}

pub(crate) fn verify_integrity_checksum(
    integrity: Ikev2IntegrityAlgorithm,
    integrity_key: &[u8],
    authenticated_message: &[u8],
    received_icv: &[u8],
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    execute_integrity_verification(
        integrity,
        integrity_key,
        authenticated_message,
        received_icv,
    )
    .map_err(map_crypto_module_error)
}

pub(crate) fn software_verify_integrity_checksum(
    integrity: Ikev2IntegrityAlgorithm,
    integrity_key: &[u8],
    authenticated_message: &[u8],
    received_icv: &[u8],
) -> Result<(), Ikev2ProtectedPayloadCryptoError> {
    validate_key_len("SK_a", integrity.key_len(), integrity_key.len())?;
    if received_icv.len() != integrity_icv_len(integrity) {
        return Err(Ikev2ProtectedPayloadCryptoError::AuthenticationFailed);
    }
    let expected = match integrity {
        Ikev2IntegrityAlgorithm::HmacSha2_256_128 => {
            hmac_sha2_256(integrity_key, &[authenticated_message])
        }
        Ikev2IntegrityAlgorithm::HmacSha2_384_192 => {
            hmac_sha2_384(integrity_key, &[authenticated_message])
        }
        Ikev2IntegrityAlgorithm::HmacSha2_512_256 => {
            hmac_sha2_512(integrity_key, &[authenticated_message])
        }
    };
    if bool::from(expected[..received_icv.len()].ct_eq(received_icv)) {
        Ok(())
    } else {
        Err(Ikev2ProtectedPayloadCryptoError::AuthenticationFailed)
    }
}

fn map_crypto_module_error(error: Ikev2CryptoModuleError) -> Ikev2ProtectedPayloadCryptoError {
    if error.operation_code() == Some(CryptoOperationErrorCode::AuthenticationFailed) {
        Ikev2ProtectedPayloadCryptoError::AuthenticationFailed
    } else {
        Ikev2ProtectedPayloadCryptoError::CryptoModuleFailure { error }
    }
}

const fn integrity_icv_len(integrity: Ikev2IntegrityAlgorithm) -> usize {
    integrity.icv_len_bits() as usize / 8
}

fn padded_ike_plaintext(
    cleartext_payloads: &[u8],
    padding_len: u8,
) -> Result<Zeroizing<Vec<u8>>, Ikev2ProtectedPayloadCryptoError> {
    let body_with_padding_len = cleartext_payloads
        .len()
        .checked_add(usize::from(padding_len))
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let capacity = body_with_padding_len
        .checked_add(1)
        .ok_or(Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(capacity));
    plaintext.extend_from_slice(cleartext_payloads);
    plaintext.resize(body_with_padding_len, 0);
    plaintext.push(padding_len);
    Ok(plaintext)
}

fn strip_ike_padding(
    plaintext: Zeroizing<Vec<u8>>,
) -> Result<Bytes, Ikev2ProtectedPayloadCryptoError> {
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

#[cfg(test)]
mod tests {
    use super::{compute_integrity_checksum, verify_integrity_checksum};
    use crate::Ikev2IntegrityAlgorithm;

    #[test]
    fn sha256_and_sha384_integrity_match_rfc4868_auth_vectors(
    ) -> Result<(), super::Ikev2ProtectedPayloadCryptoError> {
        crate::test_support::ensure_ike_crypto();
        // RFC 4868 section 2.7.2, AUTH256-1 and AUTH384-1. These fixed-key
        // authenticator vectors independently cover the left-half truncation
        // used by IKEv2 AES-CBC/HMAC profiles.
        let sha256_key = [0x0b; 32];
        let sha256_expected = [
            0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b,
            0xbd, 0xc5,
        ];
        let sha256 = compute_integrity_checksum(
            Ikev2IntegrityAlgorithm::HmacSha2_256_128,
            &sha256_key,
            b"Hi There",
            &[],
        )?;
        assert_eq!(sha256.as_slice(), sha256_expected);
        verify_integrity_checksum(
            Ikev2IntegrityAlgorithm::HmacSha2_256_128,
            &sha256_key,
            b"Hi There",
            &sha256_expected,
        )?;

        let sha384_key = [0x0b; 48];
        let sha384_expected = [
            0xb6, 0xa8, 0xd5, 0x63, 0x6f, 0x5c, 0x6a, 0x72, 0x24, 0xf9, 0x97, 0x7d, 0xcf, 0x7e,
            0xe6, 0xc7, 0xfb, 0x6d, 0x0c, 0x48, 0xcb, 0xde, 0xe9, 0x73,
        ];
        let sha384 = compute_integrity_checksum(
            Ikev2IntegrityAlgorithm::HmacSha2_384_192,
            &sha384_key,
            b"Hi There",
            &[],
        )?;
        assert_eq!(sha384.as_slice(), sha384_expected);
        verify_integrity_checksum(
            Ikev2IntegrityAlgorithm::HmacSha2_384_192,
            &sha384_key,
            b"Hi There",
            &sha384_expected,
        )?;
        Ok(())
    }
}
