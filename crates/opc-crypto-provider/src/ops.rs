//! Synchronous IKE cryptographic operation traits.
//!
//! These traits define the *operation* surface of the provider seam, grouped
//! along the capability taxonomy in [`crate::CryptoCapability`]:
//!
//! | Trait                         | Capability                                  |
//! |-------------------------------|---------------------------------------------|
//! | [`IkeHashOperations`]         | [`crate::CryptoCapability::IkeHash`]         |
//! | [`IkePrfOperations`]          | [`crate::CryptoCapability::IkePrf`]          |
//! | [`IkeIntegrityOperations`]    | [`crate::CryptoCapability::IkeIntegrity`]    |
//! | [`IkeEncryptionOperations`]   | [`crate::CryptoCapability::IkeEncryption`]   |
//! | [`IkeDiffieHellmanOperations`]| [`crate::CryptoCapability::IkeDiffieHellman`]|
//! | [`IkeSignatureOperations`]    | [`crate::CryptoCapability::IkeSignature`]    |
//! | [`IkeEntropyOperations`]      | [`crate::CryptoCapability::ApprovedEntropy`] |
//!
//! This crate still implements no cryptography: every trait here is a
//! provider-neutral contract that a cryptographic module implements elsewhere.
//! The traits are deliberately **synchronous** — they are called from
//! synchronous codec code — and **object-safe**, so an admitted module can be
//! held behind `dyn` references at a plugin boundary.
//!
//! AEAD explicit IVs and low-level caller-controlled vector inputs remain
//! operation inputs. Fresh module-owned random material is obtained through
//! [`IkeEntropyOperations`], an object-safe byte-filling boundary associated
//! with [`crate::CryptoCapability::ApprovedEntropy`].
//!
//! # Secret handling
//!
//! Secret-bearing outputs are returned as [`zeroize::Zeroizing`] buffers so
//! they are wiped on drop. Opaque handles ([`IkeDhKeyPair`],
//! [`IkeSigningKey`]) own backend-native secret state without ever exposing
//! it; implementations must wipe that state on drop and must keep their
//! `Debug` output free of key material (lengths, counts, and stable
//! identifiers only).

use std::error::Error;
use std::fmt;

use zeroize::Zeroizing;

/// Stable machine-readable operation error code.
///
/// The enum is `#[non_exhaustive]`: later slices may add codes additively.
/// Consumers must treat unknown codes as failures (fail closed).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoOperationErrorCode {
    /// The module does not implement the requested algorithm.
    UnsupportedAlgorithm,
    /// A key input had the wrong length for the algorithm.
    InvalidKeyLength,
    /// A non-key input (IV, salt, block, checksum, body) had an invalid
    /// length or shape.
    InvalidInputLength,
    /// The requested output length exceeds what the algorithm permits.
    OutputLengthUnsupported,
    /// A peer public value did not validate for the negotiated group.
    InvalidPeerPublicKey,
    /// Ephemeral key generation failed.
    KeyGenerationFailed,
    /// Key agreement failed.
    KeyAgreementFailed,
    /// Authenticated decryption or integrity verification failed.
    AuthenticationFailed,
    /// A signing key could not be loaded from its encoded form.
    InvalidSigningKey,
    /// A verification key could not be loaded from its encoded form.
    InvalidVerificationKey,
    /// The supplied key type does not match the signature algorithm.
    SignatureKeyMismatch,
    /// A signature was not encoded in the algorithm's required format.
    SignatureEncodingInvalid,
    /// Signature computation failed in the backend.
    SignatureComputationFailed,
    /// The signature does not verify over the supplied message.
    SignatureVerificationFailed,
    /// The module's admitted entropy source was unavailable.
    EntropyUnavailable,
    /// The operation failed for a reason not covered by a more specific code.
    OperationFailed,
}

impl CryptoOperationErrorCode {
    /// Stable machine-readable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedAlgorithm => "crypto_op_unsupported_algorithm",
            Self::InvalidKeyLength => "crypto_op_invalid_key_length",
            Self::InvalidInputLength => "crypto_op_invalid_input_length",
            Self::OutputLengthUnsupported => "crypto_op_output_length_unsupported",
            Self::InvalidPeerPublicKey => "crypto_op_invalid_peer_public_key",
            Self::KeyGenerationFailed => "crypto_op_key_generation_failed",
            Self::KeyAgreementFailed => "crypto_op_key_agreement_failed",
            Self::AuthenticationFailed => "crypto_op_authentication_failed",
            Self::InvalidSigningKey => "crypto_op_invalid_signing_key",
            Self::InvalidVerificationKey => "crypto_op_invalid_verification_key",
            Self::SignatureKeyMismatch => "crypto_op_signature_key_mismatch",
            Self::SignatureEncodingInvalid => "crypto_op_signature_encoding_invalid",
            Self::SignatureComputationFailed => "crypto_op_signature_computation_failed",
            Self::SignatureVerificationFailed => "crypto_op_signature_verification_failed",
            Self::EntropyUnavailable => "crypto_op_entropy_unavailable",
            Self::OperationFailed => "crypto_op_operation_failed",
        }
    }
}

impl fmt::Display for CryptoOperationErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Error returned by every operation trait in this module.
///
/// The boundary deliberately retains only a stable code. Provider-native
/// errors may contain key labels, backend paths, token identifiers, or other
/// sensitive context, so arbitrary sources never cross this public boundary
/// and neither `Debug` nor `Display` can render them.
pub struct CryptoOperationError {
    code: CryptoOperationErrorCode,
}

impl CryptoOperationError {
    /// Build an error carrying only a stable code.
    #[must_use]
    pub const fn new(code: CryptoOperationErrorCode) -> Self {
        Self { code }
    }

    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> CryptoOperationErrorCode {
        self.code
    }

    /// Stable machine-readable error code string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        self.code.as_str()
    }
}

impl fmt::Debug for CryptoOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CryptoOperationError")
            .field("code", &self.code.as_str())
            .finish()
    }
}

impl fmt::Display for CryptoOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for CryptoOperationError {}

/// IKEv2 protocol hash algorithm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeHashAlgorithm {
    /// SHA-1 for RFC 7296 NAT detection and CERTREQ authority identifiers.
    Sha1,
}

impl IkeHashAlgorithm {
    /// Stable machine-readable algorithm code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
        }
    }

    /// Digest length in octets.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
        }
    }
}

impl fmt::Display for IkeHashAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// IKEv2 negotiated pseudo-random function (RFC 7296 section 3.3.2, transform
/// type 2).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkePrfAlgorithm {
    /// PRF_HMAC_SHA2_256.
    HmacSha2_256,
    /// PRF_HMAC_SHA2_384.
    HmacSha2_384,
    /// PRF_HMAC_SHA2_512.
    HmacSha2_512,
}

impl IkePrfAlgorithm {
    /// Stable machine-readable algorithm code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HmacSha2_256 => "prf_hmac_sha2_256",
            Self::HmacSha2_384 => "prf_hmac_sha2_384",
            Self::HmacSha2_512 => "prf_hmac_sha2_512",
        }
    }

    /// PRF output length in octets.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::HmacSha2_256 => 32,
            Self::HmacSha2_384 => 48,
            Self::HmacSha2_512 => 64,
        }
    }
}

impl fmt::Display for IkePrfAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// IKEv2 negotiated integrity algorithm (RFC 4868, transform type 3).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeIntegrityAlgorithm {
    /// AUTH_HMAC_SHA2_256_128.
    HmacSha2_256_128,
    /// AUTH_HMAC_SHA2_384_192.
    HmacSha2_384_192,
    /// AUTH_HMAC_SHA2_512_256.
    HmacSha2_512_256,
}

impl IkeIntegrityAlgorithm {
    /// Stable machine-readable algorithm code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HmacSha2_256_128 => "auth_hmac_sha2_256_128",
            Self::HmacSha2_384_192 => "auth_hmac_sha2_384_192",
            Self::HmacSha2_512_256 => "auth_hmac_sha2_512_256",
        }
    }

    /// Required integrity key length in octets.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::HmacSha2_256_128 => 32,
            Self::HmacSha2_384_192 => 48,
            Self::HmacSha2_512_256 => 64,
        }
    }

    /// Truncated integrity checksum length in octets.
    #[must_use]
    pub const fn icv_len(self) -> usize {
        match self {
            Self::HmacSha2_256_128 => 16,
            Self::HmacSha2_384_192 => 24,
            Self::HmacSha2_512_256 => 32,
        }
    }
}

impl fmt::Display for IkeIntegrityAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// IKEv2 combined-mode AEAD encryption algorithm (RFC 5282, transform type 1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeAeadAlgorithm {
    /// ENCR_AES_GCM_16 with a 128-bit key.
    AesGcm16_128,
    /// ENCR_AES_GCM_16 with a 192-bit key.
    AesGcm16_192,
    /// ENCR_AES_GCM_16 with a 256-bit key.
    AesGcm16_256,
}

impl IkeAeadAlgorithm {
    /// Stable machine-readable algorithm code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AesGcm16_128 => "encr_aes_gcm_16_128",
            Self::AesGcm16_192 => "encr_aes_gcm_16_192",
            Self::AesGcm16_256 => "encr_aes_gcm_16_256",
        }
    }

    /// Raw cipher key length in octets, excluding the salt.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::AesGcm16_128 => 16,
            Self::AesGcm16_192 => 24,
            Self::AesGcm16_256 => 32,
        }
    }

    /// RFC 4106 salt length in octets.
    #[must_use]
    pub const fn salt_len(self) -> usize {
        4
    }

    /// RFC 5282 explicit IV length in octets.
    #[must_use]
    pub const fn explicit_iv_len(self) -> usize {
        8
    }

    /// Authentication tag length in octets.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        16
    }
}

impl fmt::Display for IkeAeadAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// IKEv2 AES-CBC encryption algorithm (RFC 7296 section 3.14, transform
/// type 1) used with a separate integrity transform.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeCbcAlgorithm {
    /// ENCR_AES_CBC with a 128-bit key.
    AesCbc128,
    /// ENCR_AES_CBC with a 192-bit key.
    AesCbc192,
    /// ENCR_AES_CBC with a 256-bit key.
    AesCbc256,
}

impl IkeCbcAlgorithm {
    /// Stable machine-readable algorithm code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AesCbc128 => "encr_aes_cbc_128",
            Self::AesCbc192 => "encr_aes_cbc_192",
            Self::AesCbc256 => "encr_aes_cbc_256",
        }
    }

    /// Cipher key length in octets.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::AesCbc128 => 16,
            Self::AesCbc192 => 24,
            Self::AesCbc256 => 32,
        }
    }

    /// Cipher block and IV length in octets.
    #[must_use]
    pub const fn block_len(self) -> usize {
        16
    }
}

impl fmt::Display for IkeCbcAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// IKEv2 Diffie-Hellman group (RFC 7296 section 3.3.2, transform type 4).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeDhGroup {
    /// 2048-bit MODP group (Transform ID 14).
    Modp2048,
    /// NIST P-256 ECP group (Transform ID 19).
    Ecp256,
    /// NIST P-384 ECP group (Transform ID 20).
    Ecp384,
    /// NIST P-521 ECP group (Transform ID 21).
    Ecp521,
}

impl IkeDhGroup {
    /// Stable machine-readable group code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Modp2048 => "modp_2048",
            Self::Ecp256 => "ecp_256",
            Self::Ecp384 => "ecp_384",
            Self::Ecp521 => "ecp_521",
        }
    }

    /// IKEv2 Key Exchange payload public value length in octets.
    #[must_use]
    pub const fn public_value_len(self) -> usize {
        match self {
            Self::Modp2048 => 256,
            Self::Ecp256 => 64,
            Self::Ecp384 => 96,
            Self::Ecp521 => 132,
        }
    }

    /// Fixed-width shared-secret length in octets.
    #[must_use]
    pub const fn shared_secret_len(self) -> usize {
        match self {
            Self::Modp2048 => 256,
            Self::Ecp256 => 32,
            Self::Ecp384 => 48,
            Self::Ecp521 => 66,
        }
    }
}

impl fmt::Display for IkeDhGroup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// IKE_AUTH signature algorithm (RFC 7296 method 1 and RFC 7427 method 14
/// signature primitives).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeSignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RsaPkcs1V15Sha2_256,
    /// ECDSA over P-256 with SHA-256, DER-encoded `ECDSA-Sig-Value`.
    EcdsaP256Sha2_256,
    /// ECDSA over P-384 with SHA-256, DER-encoded `ECDSA-Sig-Value`.
    EcdsaP384Sha2_256,
    /// ECDSA over P-384 with SHA-384, DER-encoded `ECDSA-Sig-Value`.
    EcdsaP384Sha2_384,
}

impl IkeSignatureAlgorithm {
    /// Stable machine-readable algorithm code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RsaPkcs1V15Sha2_256 => "rsa_pkcs1_v1_5_sha2_256",
            Self::EcdsaP256Sha2_256 => "ecdsa_p256_sha2_256",
            Self::EcdsaP384Sha2_256 => "ecdsa_p384_sha2_256",
            Self::EcdsaP384Sha2_384 => "ecdsa_p384_sha2_384",
        }
    }
}

impl fmt::Display for IkeSignatureAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// IKEv2 PRF operations ([`crate::CryptoCapability::IkePrf`]).
///
/// RFC 7296 section 2.13 `prf` and `prf+` over the negotiated HMAC-SHA2
/// family.
pub trait IkePrfOperations: Send + Sync {
    /// Whether this module can execute `algorithm`.
    fn supports_prf(&self, algorithm: IkePrfAlgorithm) -> bool;

    /// Compute `prf(key, data)`.
    ///
    /// The output is exactly [`IkePrfAlgorithm::output_len`] octets. A key
    /// longer than the underlying block length is hashed first, per HMAC.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::InvalidKeyLength`] for an empty
    /// key and [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an
    /// algorithm the module does not implement.
    fn prf(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError>;

    /// Compute `output_len` octets of RFC 7296 section 2.13 `prf+` key
    /// stream: `T1 | T2 | ...` with `Tn = prf(key, Tn-1 | seed | n)`.
    ///
    /// Requesting zero octets returns an empty buffer.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::OutputLengthUnsupported`] when
    /// `output_len` exceeds the RFC 7296 limit of 255 PRF blocks,
    /// [`CryptoOperationErrorCode::InvalidKeyLength`] for an empty key when
    /// any output is requested, and
    /// [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an algorithm
    /// the module does not implement.
    fn prf_plus(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        seed: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError>;
}

/// IKEv2 integrity operations ([`crate::CryptoCapability::IkeIntegrity`]).
pub trait IkeIntegrityOperations: Send + Sync {
    /// Whether this module can execute `algorithm`.
    fn supports_integrity(&self, algorithm: IkeIntegrityAlgorithm) -> bool;

    /// Compute the truncated integrity checksum over
    /// `message_prefix || message_suffix`.
    ///
    /// The two-part shape lets callers authenticate a header prefix plus a
    /// crypto body without concatenating; pass an empty suffix for a single
    /// buffer. The output is exactly [`IkeIntegrityAlgorithm::icv_len`]
    /// octets.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::InvalidKeyLength`] when `key` is
    /// not exactly [`IkeIntegrityAlgorithm::key_len`] octets and
    /// [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an algorithm
    /// the module does not implement.
    fn compute_integrity_checksum(
        &self,
        algorithm: IkeIntegrityAlgorithm,
        key: &[u8],
        message_prefix: &[u8],
        message_suffix: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError>;

    /// Verify a received truncated integrity checksum over
    /// `authenticated_message`.
    ///
    /// # Constant time
    ///
    /// Implementations **must** compare the expected and received checksums
    /// in constant time and must not reveal, through timing or through the
    /// returned error, which octet differed. A checksum of the wrong length
    /// fails with the same [`CryptoOperationErrorCode::AuthenticationFailed`]
    /// code as a mismatched checksum.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::AuthenticationFailed`] when the
    /// checksum does not match,
    /// [`CryptoOperationErrorCode::InvalidKeyLength`] when `key` has the
    /// wrong length, and
    /// [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an algorithm
    /// the module does not implement.
    fn verify_integrity_checksum(
        &self,
        algorithm: IkeIntegrityAlgorithm,
        key: &[u8],
        authenticated_message: &[u8],
        received_icv: &[u8],
    ) -> Result<(), CryptoOperationError>;
}

/// IKEv2 payload encryption operations
/// ([`crate::CryptoCapability::IkeEncryption`]).
///
/// IV material is explicit at this low-level boundary: AEAD explicit IVs come
/// from a caller-owned monotonic counter, while production CBC callers obtain
/// a fresh IV through the same module's [`IkeEntropyOperations`] before
/// invoking the cipher operation. Explicit IV inputs remain available for
/// deterministic vectors and make the cipher traits object-safe without a
/// generic RNG parameter.
pub trait IkeEncryptionOperations: Send + Sync {
    /// Whether this module can execute `algorithm`.
    fn supports_aead(&self, algorithm: IkeAeadAlgorithm) -> bool;

    /// Whether this module can execute `algorithm`.
    fn supports_cbc(&self, algorithm: IkeCbcAlgorithm) -> bool;

    /// Authenticate and encrypt one AEAD body.
    ///
    /// The nonce is `salt || explicit_iv` (RFC 4106/RFC 5282). The returned
    /// bytes are `explicit_iv || ciphertext || tag`, the IKEv2 `SK` crypto
    /// body layout.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::InvalidKeyLength`] when `key` is
    /// not exactly [`IkeAeadAlgorithm::key_len`] octets,
    /// [`CryptoOperationErrorCode::InvalidInputLength`] when `salt` or
    /// `explicit_iv` has the wrong length, and
    /// [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an algorithm
    /// the module does not implement.
    fn seal_aead(
        &self,
        algorithm: IkeAeadAlgorithm,
        key: &[u8],
        salt: &[u8],
        explicit_iv: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoOperationError>;

    /// Verify and decrypt one AEAD body of the form
    /// `explicit_iv || ciphertext || tag`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::AuthenticationFailed`] when the
    /// tag or associated data does not verify,
    /// [`CryptoOperationErrorCode::InvalidInputLength`] when the body is too
    /// short or `salt` has the wrong length,
    /// [`CryptoOperationErrorCode::InvalidKeyLength`] for a wrong-length
    /// key, and [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an
    /// algorithm the module does not implement.
    fn open_aead(
        &self,
        algorithm: IkeAeadAlgorithm,
        key: &[u8],
        salt: &[u8],
        associated_data: &[u8],
        protected_body: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError>;

    /// Encrypt an already block-aligned plaintext with AES-CBC (no padding
    /// is added; IKEv2 padding is protocol framing owned by the caller).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::InvalidInputLength`] when
    /// `plaintext` is empty or not a multiple of
    /// [`IkeCbcAlgorithm::block_len`] or when `iv` has the wrong length,
    /// [`CryptoOperationErrorCode::InvalidKeyLength`] for a wrong-length
    /// key, and [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an
    /// algorithm the module does not implement.
    fn encrypt_cbc(
        &self,
        algorithm: IkeCbcAlgorithm,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoOperationError>;

    /// Decrypt an AES-CBC ciphertext.
    ///
    /// This is the raw cipher primitive: callers must have verified the
    /// message integrity checksum **before** decrypting (encrypt-then-MAC).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::InvalidInputLength`] when
    /// `ciphertext` is empty or not a multiple of
    /// [`IkeCbcAlgorithm::block_len`] or when `iv` has the wrong length,
    /// [`CryptoOperationErrorCode::InvalidKeyLength`] for a wrong-length
    /// key, and [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an
    /// algorithm the module does not implement.
    fn decrypt_cbc(
        &self,
        algorithm: IkeCbcAlgorithm,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError>;
}

/// IKEv2 Diffie-Hellman operations
/// ([`crate::CryptoCapability::IkeDiffieHellman`]).
pub trait IkeDiffieHellmanOperations: Send + Sync {
    /// Whether this module can execute `group`.
    fn supports_dh_group(&self, group: IkeDhGroup) -> bool;

    /// Generate an ephemeral key pair for `group` behind an opaque handle.
    ///
    /// The handle owns the backend-native private key; the secret never
    /// crosses this boundary in any form.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::KeyGenerationFailed`] when the
    /// module cannot generate a key pair and
    /// [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for a group the
    /// module does not implement.
    fn generate_keypair(
        &self,
        group: IkeDhGroup,
    ) -> Result<Box<dyn IkeDhKeyPair>, CryptoOperationError>;
}

/// Opaque ephemeral Diffie-Hellman key pair handle.
///
/// Implementations own backend-native secret state, must wipe it on drop,
/// and must keep `Debug` output free of key material (group and lengths
/// only). The `Debug` supertrait exists so the handle can be embedded in
/// redaction-safe diagnostics.
pub trait IkeDhKeyPair: fmt::Debug + Send + Sync {
    /// Group this key pair was generated for.
    fn group(&self) -> IkeDhGroup;

    /// Public value bytes in the IKEv2 Key Exchange payload representation
    /// for the group (exactly [`IkeDhGroup::public_value_len`] octets).
    fn public_value(&self) -> &[u8];

    /// Perform key agreement with a peer public value in the IKEv2 Key
    /// Exchange payload representation.
    ///
    /// The shared secret uses the fixed-width representation for the group
    /// (exactly [`IkeDhGroup::shared_secret_len`] octets).
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::InvalidPeerPublicKey`] when the
    /// peer value has the wrong length or does not validate for the group,
    /// and [`CryptoOperationErrorCode::KeyAgreementFailed`] when agreement
    /// fails.
    fn agree(&self, peer_public_value: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError>;
}

/// IKE_AUTH signature operations
/// ([`crate::CryptoCapability::IkeSignature`]).
///
/// These are the raw signature primitives over caller-supplied message
/// bytes (for IKEv2, the RFC 7296 signed octets). RFC 7427 AUTH-data
/// framing, transcript construction, and certificate trust decisions stay
/// with the protocol layer.
pub trait IkeSignatureOperations: Send + Sync {
    /// Whether this module can verify signatures for `algorithm`.
    fn supports_signature_verification(&self, algorithm: IkeSignatureAlgorithm) -> bool;

    /// Whether this module can load a private key and sign for `algorithm`.
    fn supports_signature_generation(&self, algorithm: IkeSignatureAlgorithm) -> bool;

    /// Load a private signing key from PKCS#8 DER behind an opaque handle.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::InvalidSigningKey`] when the DER
    /// is not a valid PKCS#8 key for the algorithm and
    /// [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an algorithm
    /// the module does not implement (for example RSA signing in a build
    /// that compiles no RSA private-key operations).
    fn load_signing_key(
        &self,
        algorithm: IkeSignatureAlgorithm,
        pkcs8_der: &[u8],
    ) -> Result<Box<dyn IkeSigningKey>, CryptoOperationError>;

    /// Verify `signature` over `message` with a DER `SubjectPublicKeyInfo`
    /// public key.
    ///
    /// The signature format is the one produced by [`IkeSigningKey::sign`]
    /// for the algorithm. The caller owns the trust decision for the key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::InvalidVerificationKey`] when the
    /// SPKI does not parse,
    /// [`CryptoOperationErrorCode::SignatureKeyMismatch`] when the key type
    /// does not match the algorithm,
    /// [`CryptoOperationErrorCode::SignatureEncodingInvalid`] when the
    /// signature is not in the algorithm's required encoding,
    /// [`CryptoOperationErrorCode::SignatureVerificationFailed`] when the
    /// signature does not verify, and
    /// [`CryptoOperationErrorCode::UnsupportedAlgorithm`] for an algorithm
    /// the module does not implement.
    fn verify_signature(
        &self,
        algorithm: IkeSignatureAlgorithm,
        public_key_spki_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoOperationError>;
}

/// Opaque private signing key handle.
///
/// Implementations own backend-native secret state, must wipe it on drop,
/// and must keep `Debug` output free of key material (algorithm identifier
/// only).
pub trait IkeSigningKey: fmt::Debug + Send + Sync {
    /// Algorithm this key signs with.
    fn algorithm(&self) -> IkeSignatureAlgorithm;

    /// RSA modulus width in octets, when this is an RSA signing key.
    ///
    /// The modulus width is public key metadata, not private key material. It
    /// lets the protocol boundary enforce the fixed-width raw RSA signature
    /// encoding without exporting the private key or backend-native handle.
    /// ECDSA implementations return `None`; RSA implementations that retain
    /// the default also fail closed when their output is validated.
    fn rsa_modulus_len(&self) -> Option<usize> {
        None
    }

    /// Sign `message` (the implementation applies the algorithm's digest).
    ///
    /// The output is the raw RSASSA-PKCS1-v1_5 signature for RSA, or a
    /// DER-encoded `ECDSA-Sig-Value` for ECDSA — the X.509-compatible
    /// formats RFC 7427 requires.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::SignatureComputationFailed`] when
    /// the backend fails to sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoOperationError>;
}

/// IKEv2 protocol hashing ([`crate::CryptoCapability::IkeHash`]).
pub trait IkeHashOperations: Send + Sync {
    /// Whether this module can execute `algorithm`.
    fn supports_hash(&self, algorithm: IkeHashAlgorithm) -> bool;

    /// Hash the ordered concatenation of `parts`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::UnsupportedAlgorithm`] when the
    /// module does not implement `algorithm`.
    fn hash(
        &self,
        algorithm: IkeHashAlgorithm,
        parts: &[&[u8]],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError>;
}

/// Entropy supplied by the admitted cryptographic module.
///
/// This operation is used for fresh IKEv2 IV material. Ephemeral DH key
/// generation stays behind [`IkeDiffieHellmanOperations`] because private
/// values never cross the opaque handle boundary.
pub trait IkeEntropyOperations: Send + Sync {
    /// Fill the complete caller buffer with cryptographically secure random
    /// bytes from the module's admitted entropy source.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoOperationErrorCode::EntropyUnavailable`] if the source
    /// cannot fill the whole buffer. Partial output must be treated as secret
    /// failure material and overwritten by the implementation before return.
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoOperationError>;
}

/// Complete synchronous IKEv2 operation surface implemented by one module.
///
/// The supertraits make it impossible to install a partially shaped operation
/// object and let the process-level admission boundary bind all IKE operations
/// to the same module instance.
pub trait IkeCryptoOperations:
    IkeHashOperations
    + IkeEntropyOperations
    + IkePrfOperations
    + IkeIntegrityOperations
    + IkeEncryptionOperations
    + IkeDiffieHellmanOperations
    + IkeSignatureOperations
    + Send
    + Sync
{
}

impl<T> IkeCryptoOperations for T where
    T: IkeHashOperations
        + IkeEntropyOperations
        + IkePrfOperations
        + IkeIntegrityOperations
        + IkeEncryptionOperations
        + IkeDiffieHellmanOperations
        + IkeSignatureOperations
        + Send
        + Sync
{
}

/// Compile-time proof that every operation trait is object-safe: this
/// function only type-checks if `dyn` references to each trait exist.
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
fn assert_operation_traits_are_object_safe(
    _hash: &dyn IkeHashOperations,
    _entropy: &dyn IkeEntropyOperations,
    _prf: &dyn IkePrfOperations,
    _integrity: &dyn IkeIntegrityOperations,
    _encryption: &dyn IkeEncryptionOperations,
    _diffie_hellman: &dyn IkeDiffieHellmanOperations,
    _dh_keypair: &dyn IkeDhKeyPair,
    _signature: &dyn IkeSignatureOperations,
    _signing_key: &dyn IkeSigningKey,
) {
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::{
        CryptoOperationError, CryptoOperationErrorCode, IkeAeadAlgorithm, IkeCbcAlgorithm,
        IkeDhGroup, IkeHashAlgorithm, IkeIntegrityAlgorithm, IkePrfAlgorithm,
        IkeSignatureAlgorithm,
    };

    #[test]
    fn operation_error_codes_are_stable_and_display_prints_only_the_code() {
        let cases = [
            (
                CryptoOperationErrorCode::UnsupportedAlgorithm,
                "crypto_op_unsupported_algorithm",
            ),
            (
                CryptoOperationErrorCode::InvalidKeyLength,
                "crypto_op_invalid_key_length",
            ),
            (
                CryptoOperationErrorCode::InvalidInputLength,
                "crypto_op_invalid_input_length",
            ),
            (
                CryptoOperationErrorCode::OutputLengthUnsupported,
                "crypto_op_output_length_unsupported",
            ),
            (
                CryptoOperationErrorCode::InvalidPeerPublicKey,
                "crypto_op_invalid_peer_public_key",
            ),
            (
                CryptoOperationErrorCode::KeyGenerationFailed,
                "crypto_op_key_generation_failed",
            ),
            (
                CryptoOperationErrorCode::KeyAgreementFailed,
                "crypto_op_key_agreement_failed",
            ),
            (
                CryptoOperationErrorCode::AuthenticationFailed,
                "crypto_op_authentication_failed",
            ),
            (
                CryptoOperationErrorCode::InvalidSigningKey,
                "crypto_op_invalid_signing_key",
            ),
            (
                CryptoOperationErrorCode::InvalidVerificationKey,
                "crypto_op_invalid_verification_key",
            ),
            (
                CryptoOperationErrorCode::SignatureKeyMismatch,
                "crypto_op_signature_key_mismatch",
            ),
            (
                CryptoOperationErrorCode::SignatureEncodingInvalid,
                "crypto_op_signature_encoding_invalid",
            ),
            (
                CryptoOperationErrorCode::SignatureComputationFailed,
                "crypto_op_signature_computation_failed",
            ),
            (
                CryptoOperationErrorCode::SignatureVerificationFailed,
                "crypto_op_signature_verification_failed",
            ),
            (
                CryptoOperationErrorCode::EntropyUnavailable,
                "crypto_op_entropy_unavailable",
            ),
            (
                CryptoOperationErrorCode::OperationFailed,
                "crypto_op_operation_failed",
            ),
        ];
        let mut seen: Vec<&'static str> = Vec::new();
        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
            assert_eq!(code.to_string(), expected);
            let error = CryptoOperationError::new(code);
            assert_eq!(error.code(), code);
            assert_eq!(error.as_str(), expected);
            assert_eq!(error.to_string(), expected);
            assert!(error.source().is_none());
            assert!(!seen.contains(&expected), "duplicate code {expected}");
            seen.push(expected);
        }
    }

    #[test]
    fn operation_error_debug_and_display_print_only_the_stable_code() {
        let error = CryptoOperationError::new(CryptoOperationErrorCode::OperationFailed);
        assert_eq!(error.as_str(), "crypto_op_operation_failed");
        assert!(error.source().is_none());
        let debug = format!("{error:?}");
        assert!(debug.contains("crypto_op_operation_failed"));
        assert!(!debug.contains("source"));
    }

    #[test]
    fn algorithm_identifiers_have_stable_codes_and_consistent_lengths() {
        assert_eq!(IkeHashAlgorithm::Sha1.as_str(), "sha1");
        assert_eq!(IkeHashAlgorithm::Sha1.output_len(), 20);
        assert_eq!(IkePrfAlgorithm::HmacSha2_256.as_str(), "prf_hmac_sha2_256");
        assert_eq!(IkePrfAlgorithm::HmacSha2_384.as_str(), "prf_hmac_sha2_384");
        assert_eq!(IkePrfAlgorithm::HmacSha2_512.as_str(), "prf_hmac_sha2_512");
        assert_eq!(IkePrfAlgorithm::HmacSha2_256.output_len(), 32);
        assert_eq!(IkePrfAlgorithm::HmacSha2_384.output_len(), 48);
        assert_eq!(IkePrfAlgorithm::HmacSha2_512.output_len(), 64);

        assert_eq!(
            IkeIntegrityAlgorithm::HmacSha2_256_128.as_str(),
            "auth_hmac_sha2_256_128"
        );
        assert_eq!(
            IkeIntegrityAlgorithm::HmacSha2_384_192.as_str(),
            "auth_hmac_sha2_384_192"
        );
        assert_eq!(
            IkeIntegrityAlgorithm::HmacSha2_512_256.as_str(),
            "auth_hmac_sha2_512_256"
        );
        for (algorithm, key_len, icv_len) in [
            (IkeIntegrityAlgorithm::HmacSha2_256_128, 32, 16),
            (IkeIntegrityAlgorithm::HmacSha2_384_192, 48, 24),
            (IkeIntegrityAlgorithm::HmacSha2_512_256, 64, 32),
        ] {
            assert_eq!(algorithm.key_len(), key_len);
            assert_eq!(algorithm.icv_len(), icv_len);
        }

        for (algorithm, code, key_len) in [
            (IkeAeadAlgorithm::AesGcm16_128, "encr_aes_gcm_16_128", 16),
            (IkeAeadAlgorithm::AesGcm16_192, "encr_aes_gcm_16_192", 24),
            (IkeAeadAlgorithm::AesGcm16_256, "encr_aes_gcm_16_256", 32),
        ] {
            assert_eq!(algorithm.as_str(), code);
            assert_eq!(algorithm.to_string(), code);
            assert_eq!(algorithm.key_len(), key_len);
            assert_eq!(algorithm.salt_len(), 4);
            assert_eq!(algorithm.explicit_iv_len(), 8);
            assert_eq!(algorithm.tag_len(), 16);
        }

        for (algorithm, code, key_len) in [
            (IkeCbcAlgorithm::AesCbc128, "encr_aes_cbc_128", 16),
            (IkeCbcAlgorithm::AesCbc192, "encr_aes_cbc_192", 24),
            (IkeCbcAlgorithm::AesCbc256, "encr_aes_cbc_256", 32),
        ] {
            assert_eq!(algorithm.as_str(), code);
            assert_eq!(algorithm.key_len(), key_len);
            assert_eq!(algorithm.block_len(), 16);
        }

        for (group, code, public_len, secret_len) in [
            (IkeDhGroup::Modp2048, "modp_2048", 256, 256),
            (IkeDhGroup::Ecp256, "ecp_256", 64, 32),
            (IkeDhGroup::Ecp384, "ecp_384", 96, 48),
            (IkeDhGroup::Ecp521, "ecp_521", 132, 66),
        ] {
            assert_eq!(group.as_str(), code);
            assert_eq!(group.to_string(), code);
            assert_eq!(group.public_value_len(), public_len);
            assert_eq!(group.shared_secret_len(), secret_len);
        }

        assert_eq!(
            IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256.as_str(),
            "rsa_pkcs1_v1_5_sha2_256"
        );
        assert_eq!(
            IkeSignatureAlgorithm::EcdsaP256Sha2_256.as_str(),
            "ecdsa_p256_sha2_256"
        );
        assert_eq!(
            IkeSignatureAlgorithm::EcdsaP384Sha2_256.as_str(),
            "ecdsa_p384_sha2_256"
        );
        assert_eq!(
            IkeSignatureAlgorithm::EcdsaP384Sha2_384.as_str(),
            "ecdsa_p384_sha2_384"
        );
    }
}
