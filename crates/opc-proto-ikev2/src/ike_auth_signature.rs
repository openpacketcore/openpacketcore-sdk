//! Signature-based IKE_AUTH authentication (methods 1, 9–11, and 14).
//!
//! These helpers compute and verify the AUTH payload for RSA Digital Signature
//! (method 1, RFC 7296), ECDSA (methods 9–11, RFC 4754), and Digital Signature
//! (method 14, RFC 7427) over the
//! same RFC 7296 signed-octets transcript used by the shared-key MIC path.
//!
//! Trust scope: the verifier checks only that a signature made by the supplied
//! public key covers the transcript-bound signed octets. Extracting a public
//! key from an X.509 certificate performs no chain building, no signature
//! check on the certificate itself, no validity-period check, and no name or
//! key-usage check — the product layer owns certificate trust decisions and
//! must supply a key it already trusts (a pinned SPKI or a chain-validated
//! end-entity certificate).
//!
//! Signing defaults to ECDSA and EdDSA. RSA *signing* (method 1, and RSA under
//! method 14) is compiled in only with the `rsa-signing` cargo feature, so a
//! default build performs no RSA private-key operations and stays outside the
//! practical scope of RUSTSEC-2023-0071 (Marvin timing sidechannel in the
//! `rsa` crate). RSA *verification* of peer signatures uses public-key
//! operations only and is always available. RSA-PSS supports SHA-256/384/512,
//! matching MGF1 hashes and hash-length salts. Ed25519/Ed448 use the full
//! transcript and require the RFC 8420 Identity hash authority.
//!
//! @spec IETF RFC7296 2.15, 3.8; IETF RFC4754 7; IETF RFC7427; IETF RFC8420 2
//! @req REQ-IETF-RFC7427-IKE-AUTH-SIGNATURE-001

use std::{borrow::Cow, error::Error, fmt};

use opc_crypto_provider::{CryptoOperationErrorCode, IkeSignatureAlgorithm, IkeSigningKey};
use p256::pkcs8::EncodePublicKey as EcEncodePublicKey;
#[cfg(feature = "rsa-signing")]
use rsa::RsaPrivateKey;
use rsa::{
    pkcs8::{DecodePublicKey, EncodePublicKey as RsaEncodePublicKey},
    Pkcs1v15Sign, Pss, RsaPublicKey,
};
// RSA 0.9 exposes digest 0.10 traits; keep this adapter on its re-export.
use rsa::pkcs8::der::{Decode as RsaDerDecode, Encode as RsaDerEncode};
use rsa::sha2::{Digest, Sha256, Sha384, Sha512};
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, X509Certificate};

use crate::{
    crypto_module::{
        execute_signing_key, signature_generation_algorithm_admitted,
        signature_verification_algorithm_admitted, with_signature_generation_operation,
        with_signature_verification_operation, Ikev2CryptoModuleError,
    },
    ike_auth::{build_signed_octets, validate_signed_octets},
    ike_auth::{
        Ikev2AuthenticationPayload, Ikev2IkeAuthSignedOctets, Ikev2IkeAuthVerificationError,
    },
    sa_init_crypto::{Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial},
    signature_hash::{
        Ikev2SignatureHashAlgorithm, Ikev2SignatureHashAuthorityError,
        Ikev2SignatureHashSigningAuthority, Ikev2SignatureHashSigningAuthorization,
        Ikev2SignatureHashVerificationAuthorization,
    },
};

/// IKEv2 AUTH Method 1, RSA Digital Signature (RSASSA-PKCS1-v1_5).
///
/// RFC 7296 specifies SHA-1 for method 1; this implementation deliberately
/// signs and verifies with SHA-256 instead, matching the deployed behaviour of
/// modern peers that still offer method 1. Peers requiring RFC 7296 SHA-1
/// method 1 are not supported.
pub const IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE: u8 = 1;

/// IKEv2 AUTH Method 14, Digital Signature (RFC 7427).
pub const IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE: u8 = 14;

/// RFC 4754 AUTH Method 9: ECDSA P-256 with SHA-256 and fixed-width r||s.
pub const IKEV2_AUTH_METHOD_ECDSA_SHA2_256: u8 = 9;
/// RFC 4754 AUTH Method 10: ECDSA P-384 with SHA-384 and fixed-width r||s.
pub const IKEV2_AUTH_METHOD_ECDSA_SHA2_384: u8 = 10;
/// RFC 4754 AUTH Method 11: ECDSA P-521 with SHA-512 and fixed-width r||s.
pub const IKEV2_AUTH_METHOD_ECDSA_SHA2_512: u8 = 11;

/// DER `AlgorithmIdentifier` for `sha256WithRSAEncryption`
/// (OID 1.2.840.113549.1.1.11 with NULL parameters).
pub const RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
];

/// DER `AlgorithmIdentifier` for `ecdsa-with-SHA256`
/// (OID 1.2.840.10045.4.3.2, absent parameters per RFC 5758).
pub const RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

/// DER `AlgorithmIdentifier` for `ecdsa-with-SHA384`
/// (OID 1.2.840.10045.4.3.3, absent parameters per RFC 5758).
pub const RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
];

/// DER AlgorithmIdentifier for ECDSA with SHA-512 (RFC 7427).
pub const RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_512: [u8; 12] = [
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04,
];
/// DER AlgorithmIdentifier for pure Ed25519, with absent parameters (RFC 8420).
pub const RFC8420_ALGORITHM_IDENTIFIER_ED25519: [u8; 7] =
    [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
/// DER AlgorithmIdentifier for pure Ed448, with absent parameters (RFC 8420).
pub const RFC8420_ALGORITHM_IDENTIFIER_ED448: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71];
/// DER AlgorithmIdentifier for RSA-PSS with SHA-256, matching MGF1 hash
/// and a 32-octet salt. The default trailerField is omitted per DER.
pub const RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_256: [u8; 67] = [
    0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0,
    0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03,
    0x02, 0x01, 0x20,
];
/// DER AlgorithmIdentifier for RSA-PSS with SHA-384, matching MGF1 hash
/// and a 48-octet salt. The default trailerField is omitted per DER.
pub const RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_384: [u8; 67] = [
    0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0,
    0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xa2, 0x03,
    0x02, 0x01, 0x30,
];
/// DER AlgorithmIdentifier for RSA-PSS with SHA-512, matching MGF1 hash
/// and a 64-octet salt. The default trailerField is omitted per DER.
pub const RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_512: [u8; 67] = [
    0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0,
    0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xa2, 0x03,
    0x02, 0x01, 0x40,
];

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_NAMED_CURVE_P256: &str = "1.2.840.10045.3.1.7";
const OID_NAMED_CURVE_P384: &str = "1.3.132.0.34";
const OID_NAMED_CURVE_P521: &str = "1.3.132.0.35";
const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";

/// AUTH method selector for signature-based IKE_AUTH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SignatureAuthMethod {
    /// Method 1, RSA Digital Signature (RSASSA-PKCS1-v1_5 with SHA-256).
    ///
    /// Signing with this method requires the `rsa-signing` cargo feature.
    #[cfg(feature = "rsa-signing")]
    RsaDigitalSignature,
    /// Method 9, ECDSA with SHA-256 (RFC 4754).
    EcdsaSha2_256,
    /// Method 10, ECDSA with SHA-384 (RFC 4754).
    EcdsaSha2_384,
    /// Method 11, ECDSA with SHA-512 (RFC 4754).
    EcdsaSha2_512,
    /// Method 14, RFC 7427 Digital Signature.
    DigitalSignature,
}

impl Ikev2SignatureAuthMethod {
    /// Return the RFC 7296 AUTH Method octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            #[cfg(feature = "rsa-signing")]
            Self::RsaDigitalSignature => IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE,
            Self::EcdsaSha2_256 => IKEV2_AUTH_METHOD_ECDSA_SHA2_256,
            Self::EcdsaSha2_384 => IKEV2_AUTH_METHOD_ECDSA_SHA2_384,
            Self::EcdsaSha2_512 => IKEV2_AUTH_METHOD_ECDSA_SHA2_512,
            Self::DigitalSignature => IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
        }
    }
}

/// Responder or initiator signing key plus chosen AUTH method.
///
/// Construct through the RSA, ECDSA, or EdDSA PKCS#8 constructors, which
/// reject method/key combinations that IKEv2 does not allow. The wrapped RustCrypto key types zeroize their
/// key material on drop, and `Debug` never prints key bytes.
pub struct Ikev2SignatureAuthKey {
    method: Ikev2SignatureAuthMethod,
    algorithm: IkeSignatureAlgorithm,
    signing_key: Box<dyn IkeSigningKey>,
}

impl Ikev2SignatureAuthKey {
    /// Load an RSA private key from PKCS#8 DER for method 1 or method 14.
    ///
    /// Available only with the `rsa-signing` cargo feature; see the module
    /// documentation for the RUSTSEC-2023-0071 trade-off. Prefer the ECDSA
    /// constructors.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SignatureKeyError`] when the DER is not a valid PKCS#8
    /// RSA private key.
    #[cfg(feature = "rsa-signing")]
    pub fn rsa_pkcs8_der(
        method: Ikev2SignatureAuthMethod,
        pkcs8_der: &[u8],
    ) -> Result<Self, Ikev2SignatureKeyError> {
        if !matches!(
            method,
            Ikev2SignatureAuthMethod::RsaDigitalSignature
                | Ikev2SignatureAuthMethod::DigitalSignature
        ) {
            return Err(Ikev2SignatureKeyError::UnsupportedSignatureAlgorithm);
        }
        let algorithm = IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256;
        let key = load_admitted_signing_key(
            algorithm,
            pkcs8_der,
            Ikev2SignatureKeyError::RsaPrivateKeyParse,
        )?;
        Ok(Self {
            method,
            algorithm,
            signing_key: key,
        })
    }

    /// Load an ECDSA P-256 private key from PKCS#8 DER for method 14.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SignatureKeyError`] when the DER is not a valid PKCS#8
    /// P-256 private key.
    pub fn ecdsa_p256_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        let algorithm = IkeSignatureAlgorithm::EcdsaP256Sha2_256;
        let key = load_admitted_signing_key(
            algorithm,
            pkcs8_der,
            Ikev2SignatureKeyError::EcdsaPrivateKeyParse,
        )?;
        Ok(Self {
            method: Ikev2SignatureAuthMethod::DigitalSignature,
            algorithm,
            signing_key: key,
        })
    }

    /// Load an ECDSA P-384 private key from PKCS#8 DER for method 14.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SignatureKeyError`] when the DER is not a valid PKCS#8
    /// P-384 private key.
    pub fn ecdsa_p384_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        let algorithm = IkeSignatureAlgorithm::EcdsaP384Sha2_384;
        let key = load_admitted_signing_key(
            algorithm,
            pkcs8_der,
            Ikev2SignatureKeyError::EcdsaPrivateKeyParse,
        )?;
        Ok(Self {
            method: Ikev2SignatureAuthMethod::DigitalSignature,
            algorithm,
            signing_key: key,
        })
    }

    /// Load an ECDSA P-521 key for method 14 with SHA-512.
    ///
    /// # Errors
    /// Returns an error for invalid PKCS#8 or a key not admitted by the module.
    pub fn ecdsa_p521_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        Self::from_algorithm(
            Ikev2SignatureAuthMethod::DigitalSignature,
            IkeSignatureAlgorithm::EcdsaP521Sha2_512,
            pkcs8_der,
            Ikev2SignatureKeyError::EcdsaPrivateKeyParse,
        )
    }

    /// Load an ECDSA key for RFC 4754 method 9, 10, or 11.
    ///
    /// These methods use fixed-width r||s and do not require RFC 7427 authority.
    /// The key must match the curve selected by `method`.
    ///
    /// # Errors
    /// Returns an error for any other method, invalid key, or module rejection.
    pub fn ecdsa_rfc4754_pkcs8_der(
        method: Ikev2SignatureAuthMethod,
        pkcs8_der: &[u8],
    ) -> Result<Self, Ikev2SignatureKeyError> {
        let algorithm = legacy_ecdsa_algorithm(method.as_u8())
            .ok_or(Ikev2SignatureKeyError::UnsupportedSignatureAlgorithm)?;
        Self::from_algorithm(
            method,
            algorithm,
            pkcs8_der,
            Ikev2SignatureKeyError::EcdsaPrivateKeyParse,
        )
    }

    /// Load an RSA-PSS key for method 14 with SHA-256, SHA-384, or SHA-512.
    ///
    /// MGF1 uses the same hash and the salt has the hash output length.
    /// Available only with `rsa-signing`.
    ///
    /// # Errors
    /// Returns an error for another hash, invalid PKCS#8, or module rejection.
    #[cfg(feature = "rsa-signing")]
    pub fn rsa_pss_pkcs8_der(
        hash: Ikev2SignatureHashAlgorithm,
        pkcs8_der: &[u8],
    ) -> Result<Self, Ikev2SignatureKeyError> {
        let algorithm = match hash {
            Ikev2SignatureHashAlgorithm::Sha2_256 => IkeSignatureAlgorithm::RsaPssSha2_256,
            Ikev2SignatureHashAlgorithm::Sha2_384 => IkeSignatureAlgorithm::RsaPssSha2_384,
            Ikev2SignatureHashAlgorithm::Sha2_512 => IkeSignatureAlgorithm::RsaPssSha2_512,
            _ => return Err(Ikev2SignatureKeyError::UnsupportedSignatureAlgorithm),
        };
        Self::from_algorithm(
            Ikev2SignatureAuthMethod::DigitalSignature,
            algorithm,
            pkcs8_der,
            Ikev2SignatureKeyError::RsaPrivateKeyParse,
        )
    }

    /// Load a pure Ed25519 key for method 14 with the Identity hash (RFC 8420).
    ///
    /// # Errors
    /// Returns an error for invalid PKCS#8 or module rejection.
    pub fn ed25519_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        Self::from_algorithm(
            Ikev2SignatureAuthMethod::DigitalSignature,
            IkeSignatureAlgorithm::Ed25519,
            pkcs8_der,
            Ikev2SignatureKeyError::EdDsaPrivateKeyParse,
        )
    }

    /// Load a pure Ed448 key for method 14 with the Identity hash (RFC 8420).
    ///
    /// # Errors
    /// Returns an error for invalid PKCS#8 or module rejection.
    pub fn ed448_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        Self::from_algorithm(
            Ikev2SignatureAuthMethod::DigitalSignature,
            IkeSignatureAlgorithm::Ed448,
            pkcs8_der,
            Ikev2SignatureKeyError::EdDsaPrivateKeyParse,
        )
    }

    /// Load a P-256 key for RFC 4754 method 9 using fixed-width r||s.
    /// # Errors
    /// Refuses an invalid key or a key not admitted by the installed module.
    pub fn ecdsa_p256_sha256_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        Self::ecdsa_rfc4754_pkcs8_der(Ikev2SignatureAuthMethod::EcdsaSha2_256, pkcs8_der)
    }

    /// Load a P-384 key for RFC 4754 method 10 using fixed-width r||s.
    /// # Errors
    /// Refuses an invalid key or a key not admitted by the installed module.
    pub fn ecdsa_p384_sha384_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        Self::ecdsa_rfc4754_pkcs8_der(Ikev2SignatureAuthMethod::EcdsaSha2_384, pkcs8_der)
    }

    /// Load a P-521 key for RFC 4754 method 11 using fixed-width r||s.
    /// # Errors
    /// Refuses an invalid key or a key not admitted by the installed module.
    pub fn ecdsa_p521_sha512_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        Self::ecdsa_rfc4754_pkcs8_der(Ikev2SignatureAuthMethod::EcdsaSha2_512, pkcs8_der)
    }

    /// Load an RSA-PSS key for method 14 with SHA-256 and matching MGF1/salt length.
    /// # Errors
    /// Refuses an invalid key or a key not admitted by the installed module.
    #[cfg(feature = "rsa-signing")]
    pub fn rsa_pss_sha256_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        Self::rsa_pss_pkcs8_der(Ikev2SignatureHashAlgorithm::Sha2_256, pkcs8_der)
    }

    /// Load an RSA-PSS key for method 14 with SHA-384 and matching MGF1/salt length.
    /// # Errors
    /// Refuses an invalid key or a key not admitted by the installed module.
    #[cfg(feature = "rsa-signing")]
    pub fn rsa_pss_sha384_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        Self::rsa_pss_pkcs8_der(Ikev2SignatureHashAlgorithm::Sha2_384, pkcs8_der)
    }

    /// Load an RSA-PSS key for method 14 with SHA-512 and matching MGF1/salt length.
    /// # Errors
    /// Refuses an invalid key or a key not admitted by the installed module.
    #[cfg(feature = "rsa-signing")]
    pub fn rsa_pss_sha512_pkcs8_der(pkcs8_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        Self::rsa_pss_pkcs8_der(Ikev2SignatureHashAlgorithm::Sha2_512, pkcs8_der)
    }

    fn from_algorithm(
        method: Ikev2SignatureAuthMethod,
        algorithm: IkeSignatureAlgorithm,
        pkcs8_der: &[u8],
        parse_error: Ikev2SignatureKeyError,
    ) -> Result<Self, Ikev2SignatureKeyError> {
        Ok(Self {
            method,
            algorithm,
            signing_key: load_admitted_signing_key(algorithm, pkcs8_der, parse_error)?,
        })
    }

    /// Return the AUTH method this key signs for.
    pub const fn method(&self) -> Ikev2SignatureAuthMethod {
        self.method
    }
}

impl fmt::Debug for Ikev2SignatureAuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SignatureAuthKey")
            .field("method", &self.method)
            .field("key_kind", &self.algorithm.as_str())
            .finish()
    }
}

fn load_admitted_signing_key(
    algorithm: IkeSignatureAlgorithm,
    pkcs8_der: &[u8],
    parse_error: Ikev2SignatureKeyError,
) -> Result<Box<dyn IkeSigningKey>, Ikev2SignatureKeyError> {
    let key = with_signature_generation_operation(algorithm, |module| {
        module.load_signing_key(algorithm, pkcs8_der)
    })
    .map_err(|error| {
        if error.operation_code() == Some(CryptoOperationErrorCode::InvalidSigningKey) {
            parse_error
        } else {
            Ikev2SignatureKeyError::CryptoModuleFailure { error }
        }
    })?;
    if key.algorithm() != algorithm {
        return Err(Ikev2SignatureKeyError::CryptoModuleFailure {
            error: Ikev2CryptoModuleError::invalid_output(),
        });
    }
    Ok(key)
}

/// Trusted public key used to verify signature AUTH.
///
/// This is the caller's trust anchor input: a pinned SPKI or the key of a
/// certificate the product layer has already validated. See the module
/// documentation for exactly what verification does and does not check.
pub enum Ikev2SignaturePublicKey {
    /// RSA public key.
    Rsa(Box<RsaPublicKey>),
    /// ECDSA P-256 public key.
    EcdsaP256(p256::ecdsa::VerifyingKey),
    /// ECDSA P-384 public key.
    EcdsaP384(p384::ecdsa::VerifyingKey),
    /// ECDSA P-521 public key.
    EcdsaP521(p521::ecdsa::VerifyingKey),
    /// Pure Ed25519 public key.
    Ed25519(ed25519_dalek::VerifyingKey),
    /// Pure Ed448 public key.
    Ed448(ed448_goldilocks_plus::VerifyingKey),
}

impl Ikev2SignaturePublicKey {
    /// Parse a DER SubjectPublicKeyInfo into a typed verification key.
    ///
    /// Supports RSA, ECDSA P-256/P-384/P-521 and Ed25519/Ed448. EdDSA
    /// parameters must be absent and every SPKI must have zero unused bits.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SignatureKeyError`] when the SPKI is malformed, has
    /// trailing data, or uses an unsupported algorithm or curve.
    pub fn from_spki_der(spki_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        let (remainder, spki) = SubjectPublicKeyInfo::from_der(spki_der)
            .map_err(|_| Ikev2SignatureKeyError::SpkiParse)?;
        if !remainder.is_empty() {
            return Err(Ikev2SignatureKeyError::SpkiTrailingData);
        }
        Self::from_parsed_spki(spki_der, &spki)
    }

    /// Extract the end-entity SubjectPublicKeyInfo from a DER X.509
    /// certificate and parse it into a typed verification key.
    ///
    /// This performs no certificate validation of any kind — no chain, no
    /// certificate signature check, no validity period, no name or key-usage
    /// constraints. The caller must only pass certificates it already trusts.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SignatureKeyError`] when the certificate is malformed,
    /// has trailing data, or its public key algorithm or curve is unsupported.
    pub fn from_x509_certificate_der(cert_der: &[u8]) -> Result<Self, Ikev2SignatureKeyError> {
        let (remainder, certificate) = X509Certificate::from_der(cert_der)
            .map_err(|_| Ikev2SignatureKeyError::CertificateParse)?;
        if !remainder.is_empty() {
            return Err(Ikev2SignatureKeyError::CertificateTrailingData);
        }
        let spki = certificate.public_key();
        Self::from_parsed_spki(spki.raw, spki)
    }

    fn from_parsed_spki(
        spki_der: &[u8],
        spki: &SubjectPublicKeyInfo<'_>,
    ) -> Result<Self, Ikev2SignatureKeyError> {
        if spki.subject_public_key.unused_bits != 0 {
            return Err(Ikev2SignatureKeyError::SpkiParse);
        }
        let algorithm_oid = spki.algorithm.algorithm.to_id_string();
        match algorithm_oid.as_str() {
            OID_RSA_ENCRYPTION => {
                let key = RsaPublicKey::from_public_key_der(spki_der)
                    .map_err(|_| Ikev2SignatureKeyError::RsaPublicKeyParse)?;
                Ok(Self::Rsa(Box::new(key)))
            }
            OID_EC_PUBLIC_KEY => {
                let curve_oid = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|parameters| parameters.as_oid().ok())
                    .ok_or(Ikev2SignatureKeyError::UnsupportedEcCurve)?
                    .to_id_string();
                let point = &spki.subject_public_key.data;
                match curve_oid.as_str() {
                    OID_NAMED_CURVE_P256 => p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                        .map(Self::EcdsaP256)
                        .map_err(|_| Ikev2SignatureKeyError::EcdsaPublicKeyParse),
                    OID_NAMED_CURVE_P384 => p384::ecdsa::VerifyingKey::from_sec1_bytes(point)
                        .map(Self::EcdsaP384)
                        .map_err(|_| Ikev2SignatureKeyError::EcdsaPublicKeyParse),
                    OID_NAMED_CURVE_P521 => p521::ecdsa::VerifyingKey::from_sec1_bytes(point)
                        .map(Self::EcdsaP521)
                        .map_err(|_| Ikev2SignatureKeyError::EcdsaPublicKeyParse),
                    _ => Err(Ikev2SignatureKeyError::UnsupportedEcCurve),
                }
            }
            OID_ED25519 | OID_ED448 => {
                if spki.algorithm.parameters.is_some() {
                    return Err(Ikev2SignatureKeyError::SpkiParse);
                }
                let bytes = spki.subject_public_key.data.as_ref();
                if algorithm_oid == OID_ED25519 {
                    let encoded = <&[u8; 32]>::try_from(bytes)
                        .map_err(|_| Ikev2SignatureKeyError::EdDsaPublicKeyParse)?;
                    let public = ed25519_dalek::VerifyingKey::from_bytes(encoded)
                        .map_err(|_| Ikev2SignatureKeyError::EdDsaPublicKeyParse)?;
                    if public.is_weak() {
                        return Err(Ikev2SignatureKeyError::EdDsaPublicKeyParse);
                    }
                    Ok(Self::Ed25519(public))
                } else {
                    let encoded = <&[u8; 57]>::try_from(bytes)
                        .map_err(|_| Ikev2SignatureKeyError::EdDsaPublicKeyParse)?;
                    let public = ed448_goldilocks_plus::VerifyingKey::from_bytes(encoded)
                        .map_err(|_| Ikev2SignatureKeyError::EdDsaPublicKeyParse)?;
                    if !bool::from(public.to_edwards().is_torsion_free()) {
                        return Err(Ikev2SignatureKeyError::EdDsaPublicKeyParse);
                    }
                    Ok(Self::Ed448(public))
                }
            }
            _ => Err(Ikev2SignatureKeyError::UnsupportedPublicKeyAlgorithm),
        }
    }
}

impl fmt::Debug for Ikev2SignaturePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2SignaturePublicKey")
            .field(
                "key_kind",
                &match self {
                    Self::Rsa(_) => "rsa",
                    Self::EcdsaP256(_) => "ecdsa_p256",
                    Self::EcdsaP384(_) => "ecdsa_p384",
                    Self::EcdsaP521(_) => "ecdsa_p521",
                    Self::Ed25519(_) => "ed25519",
                    Self::Ed448(_) => "ed448",
                },
            )
            .finish()
    }
}

/// One sealed authorization to verify a locally generated method-14 AUTH.
///
/// Obtain this value from
/// [`Ikev2SignatureHashSigningAuthority::authorize_local_auth_self_verification`].
/// It binds one operation to the exact successful RFC 7427 negotiation, local
/// IKE role, retained request and response, direction-correct opposite-message
/// Nonce, exact identity body, selected signature hash, and local public
/// credential. It is deliberately neither `Clone` nor `Copy` and is consumed
/// by [`verify_local_ike_auth_signature`].
///
/// Packet, identity, nonce, signature, and credential material are private and
/// omitted from `Debug`.
pub struct Ikev2LocalAuthSelfVerificationAuthorization<'a> {
    hash_authorization: Ikev2SignatureHashSigningAuthorization<'a>,
    signed_octets: Ikev2IkeAuthSignedOctets<'a>,
    selected_hash: Ikev2SignatureHashAlgorithm,
    signature_algorithm: IkeSignatureAlgorithm,
    local_public_credential: &'a Ikev2SignaturePublicKey,
}

impl fmt::Debug for Ikev2LocalAuthSelfVerificationAuthorization<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ikev2LocalAuthSelfVerificationAuthorization")
            .field("selected_hash", &self.selected_hash)
            .finish_non_exhaustive()
    }
}

impl Ikev2SignatureHashSigningAuthority {
    /// Bind local method-14 self-verification to the selected signing algorithm.
    ///
    /// Use this variant when a key/hash pair permits several schemes, such as
    /// RSA-PSS and PKCS#1 v1.5 with SHA-256. The signature scheme and public
    /// credential are fixed in the returned one-operation authorization.
    ///
    /// # Errors
    /// Returns an error for a non-method-14 key, a mismatched transcript,
    /// unauthorized hash, incompatible public key, or unadmitted algorithm.
    pub fn authorize_local_auth_self_verification_with_signing_key<'a>(
        &'a self,
        request: &'a [u8],
        response: &'a [u8],
        signed_octets: Ikev2IkeAuthSignedOctets<'a>,
        signing_key: &Ikev2SignatureAuthKey,
        local_public_credential: &'a Ikev2SignaturePublicKey,
    ) -> Result<Ikev2LocalAuthSelfVerificationAuthorization<'a>, Ikev2IkeAuthVerificationError>
    {
        validate_signed_octets(signed_octets)?;
        if signing_key.method != Ikev2SignatureAuthMethod::DigitalSignature {
            return Err(
                Ikev2IkeAuthVerificationError::UnsupportedAuthenticationMethod {
                    method: signing_key.method.as_u8(),
                },
            );
        }
        let selected_hash = signature_hash_for_algorithm(signing_key.algorithm)?;
        let hash_authorization = self
            .for_exchange(request, response)
            .map_err(|_| Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch)?;
        hash_authorization
            .validate(selected_hash, signed_octets)
            .map_err(map_signature_hash_authority_error)?;
        let signature_algorithm = signature_algorithm_for_public_key_and_identifier(
            local_public_credential,
            signature_identifier(signing_key.algorithm)?,
            selected_hash,
        )?;
        if signature_algorithm != signing_key.algorithm {
            return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch);
        }
        let generation_admitted = signature_generation_algorithm_admitted(signature_algorithm)
            .map_err(|error| Ikev2IkeAuthVerificationError::CryptoModuleFailure { error })?;
        let verification_admitted = signature_verification_algorithm_admitted(signature_algorithm)
            .map_err(|error| Ikev2IkeAuthVerificationError::CryptoModuleFailure { error })?;
        if !generation_admitted || !verification_admitted {
            return Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported);
        }
        Ok(Ikev2LocalAuthSelfVerificationAuthorization {
            hash_authorization,
            signed_octets,
            selected_hash,
            signature_algorithm,
            local_public_credential,
        })
    }

    /// Bind one local AUTH self-verification operation to exact inputs.
    ///
    /// This is intentionally separate from peer verification authority. The
    /// supplied signed-octet inputs must name the local role established by
    /// the negotiation and must contain that role's exact retained SA_INIT
    /// message and direction-correct opposite-message Nonce. The identity
    /// body, selected hash, and local public credential are captured inside
    /// the returned non-copyable authorization and cannot be substituted at
    /// the verification call.
    ///
    /// Call this after choosing the local method-14 signing credential and
    /// before transmitting the generated AUTH payload. The SDK verifies the
    /// public credential cryptographically; certificate-chain, validity,
    /// identity, and key-usage policy remain caller-owned.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2IkeAuthVerificationError`] when signed-octet inputs are
    /// malformed, the transcript/role/Nonce differs from the negotiation, the
    /// selected hash was not authorized for local signing, or the credential
    /// cannot execute that selected hash through both admitted generation and
    /// verification operations.
    pub fn authorize_local_auth_self_verification<'a>(
        &'a self,
        request: &'a [u8],
        response: &'a [u8],
        signed_octets: Ikev2IkeAuthSignedOctets<'a>,
        selected_hash: Ikev2SignatureHashAlgorithm,
        local_public_credential: &'a Ikev2SignaturePublicKey,
    ) -> Result<Ikev2LocalAuthSelfVerificationAuthorization<'a>, Ikev2IkeAuthVerificationError>
    {
        validate_signed_octets(signed_octets)?;
        let hash_authorization = self
            .for_exchange(request, response)
            .map_err(|_| Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch)?;
        hash_authorization
            .validate(selected_hash, signed_octets)
            .map_err(map_signature_hash_authority_error)?;
        let signature_algorithm =
            signature_algorithm_for_public_key_and_hash(local_public_credential, selected_hash)?;
        let generation_admitted = signature_generation_algorithm_admitted(signature_algorithm)
            .map_err(|error| Ikev2IkeAuthVerificationError::CryptoModuleFailure { error })?;
        let verification_admitted = signature_verification_algorithm_admitted(signature_algorithm)
            .map_err(|error| Ikev2IkeAuthVerificationError::CryptoModuleFailure { error })?;
        if !generation_admitted || !verification_admitted {
            return Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported);
        }

        Ok(Ikev2LocalAuthSelfVerificationAuthorization {
            hash_authorization,
            signed_octets,
            selected_hash,
            signature_algorithm,
            local_public_credential,
        })
    }
}

/// Compute signature AUTH data over the RFC 7296 signed octets.
///
/// For method 1 the returned AUTH data is the raw RSASSA-PKCS1-v1_5 SHA-256
/// signature. For methods 9–11 it is fixed-width r||s. For method 14 it is
/// the RFC 7427 framing:
/// `len(AlgorithmIdentifier) || DER(AlgorithmIdentifier) || signature`, where
/// the signature uses the selected PKCS#1 v1.5, RSA-PSS, DER ECDSA, or
/// pure EdDSA encoding, matching X.509 formats as RFC 7427 requires.
///
/// Feed the result into `build_ike_auth_authentication_payload` with
/// `key.method().as_u8()` as the AUTH method.
/// RFC 7427 method 14 requires a one-operation
/// `signature_hash_authorization` bound to both peers' exact `IKE_SA_INIT`
/// messages and the opposite message's validated Nonce payload; methods 1
/// and 9–11 ignore this argument.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthVerificationError`] when the transcript inputs are
/// structurally invalid, the method/key combination is not allowed (method 1
/// requires an RSA key), RFC 7427 authority is absent or mismatched, or the
/// signing backend fails.
pub fn compute_ike_auth_signature(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    key: &Ikev2SignatureAuthKey,
    signature_hash_authorization: Option<Ikev2SignatureHashSigningAuthorization<'_>>,
) -> Result<Vec<u8>, Ikev2IkeAuthVerificationError> {
    validate_signed_octets(signed_octets)?;

    #[cfg(feature = "rsa-signing")]
    if key.method == Ikev2SignatureAuthMethod::RsaDigitalSignature {
        if key.algorithm != IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256 {
            return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch);
        }
        let signed = build_signed_octets(profile.prf(), key_material, signed_octets)?;
        let signature = execute_signing_key(key.algorithm, key.signing_key.as_ref(), &signed)
            .map_err(map_signature_module_error)?;
        return Ok(signature);
    }

    if let Some(algorithm) = legacy_ecdsa_algorithm(key.method.as_u8()) {
        if key.algorithm != algorithm {
            return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch);
        }
        let signed = build_signed_octets(profile.prf(), key_material, signed_octets)?;
        let signature = execute_signing_key(algorithm, key.signing_key.as_ref(), &signed)
            .map_err(map_signature_module_error)?;
        return ecdsa_signature_to_fixed(algorithm, &signature);
    }

    let signature_hash = signature_hash_for_algorithm(key.algorithm)?;
    require_signing_hash_authority(signature_hash_authorization, signature_hash, signed_octets)?;
    let signed = build_signed_octets(profile.prf(), key_material, signed_octets)?;
    let signature = execute_signing_key(key.algorithm, key.signing_key.as_ref(), &signed)
        .map_err(map_signature_module_error)?;

    let algorithm_identifier = signature_identifier(key.algorithm)?;
    let algorithm_identifier_len = u8::try_from(algorithm_identifier.len())
        .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)?;
    let mut auth_data = Vec::with_capacity(1 + algorithm_identifier.len() + signature.len());
    auth_data.push(algorithm_identifier_len);
    auth_data.extend_from_slice(algorithm_identifier);
    auth_data.extend_from_slice(&signature);
    Ok(auth_data)
}

/// Verify a signature AUTH payload (method 1, 9–11, or 14) over the signed octets.
///
/// The supplied public key is the caller's trust decision — a pinned SPKI or a
/// key extracted from a certificate the product layer already validated. Any
/// AUTH method other than 1, 9–11, or 14 (including shared-key method 2, which
/// [`crate::verify_ike_auth_shared_key_mic`] owns) fails with
/// `UnsupportedAuthenticationMethod`.
/// RFC 7427 method 14 additionally requires direction-specific
/// `signature_hash_authorization` bound to both exact SA_INIT messages and the
/// opposite message's validated Nonce payload; methods 1 and 9–11 ignore it.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthVerificationError`] when the transcript inputs are
/// structurally invalid, the AUTH data framing is malformed, the algorithm or
/// method is unsupported, the key type does not match the signature algorithm,
/// RFC 7427 authority is absent or mismatched, or the signature does not
/// verify.
pub fn verify_ike_auth_signature(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    public_key: &Ikev2SignaturePublicKey,
    authentication: &Ikev2AuthenticationPayload<'_>,
    signature_hash_authorization: Option<Ikev2SignatureHashVerificationAuthorization<'_>>,
) -> Result<(), Ikev2IkeAuthVerificationError> {
    validate_signed_octets(signed_octets)?;

    let (algorithm, signature, signature_hash) = match authentication.auth_method {
        IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE => match public_key {
            Ikev2SignaturePublicKey::Rsa(_) => (
                IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256,
                Cow::Borrowed(authentication.auth_data),
                None,
            ),
            _ => return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch),
        },
        IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE => {
            let (algorithm, signature, hash) =
                decode_method14_signature(public_key, authentication.auth_data)?;
            (algorithm, Cow::Borrowed(signature), Some(hash))
        }
        method => {
            let algorithm = legacy_ecdsa_algorithm(method)
                .ok_or(Ikev2IkeAuthVerificationError::UnsupportedAuthenticationMethod { method })?;
            let hash = signature_hash_for_algorithm(algorithm)?;
            let selected = signature_algorithm_for_public_key_and_identifier(
                public_key,
                signature_identifier(algorithm)?,
                hash,
            )?;
            if selected != algorithm {
                return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch);
            }
            (
                algorithm,
                Cow::Owned(ecdsa_signature_to_der(algorithm, authentication.auth_data)?),
                None,
            )
        }
    };
    if let Some(signature_hash) = signature_hash {
        require_verification_hash_authority(
            signature_hash_authorization,
            signature_hash,
            signed_octets,
        )?;
    }
    verify_signature_bytes(
        profile,
        key_material,
        signed_octets,
        public_key,
        algorithm,
        &signature,
    )
}

/// Verify a locally generated RFC 7427 method-14 AUTH before transmission.
///
/// This operation is not peer authentication. It consumes a sealed
/// [`Ikev2LocalAuthSelfVerificationAuthorization`] minted by the local signing
/// authority and verifies that the generated AUTH wire value matches every
/// input captured there: the exact negotiation and local role, both retained
/// SA_INIT messages, the direction-correct opposite-message Nonce, the exact
/// identity body, the selected signature hash, and the local public
/// credential.
///
/// Every AUTH method other than method 14 is rejected. The ordinary
/// [`verify_ike_auth_signature`] boundary continues to require the remote-peer
/// verification authority and cannot consume this local authorization.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthVerificationError`] for method/hash/algorithm
/// substitution, a stale or directionally invalid authorization, malformed
/// AUTH framing, inconsistent key material, credential or signature mismatch,
/// or an admitted crypto-module failure. All structural and authority checks
/// complete before transcript PRF or signature verification executes.
pub fn verify_local_ike_auth_signature(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    authentication: &Ikev2AuthenticationPayload<'_>,
    authorization: Ikev2LocalAuthSelfVerificationAuthorization<'_>,
) -> Result<(), Ikev2IkeAuthVerificationError> {
    if authentication.auth_method != IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE {
        return Err(
            Ikev2IkeAuthVerificationError::UnsupportedAuthenticationMethod {
                method: authentication.auth_method,
            },
        );
    }

    let (algorithm, signature, signature_hash) = decode_method14_signature(
        authorization.local_public_credential,
        authentication.auth_data,
    )?;
    if signature_hash != authorization.selected_hash
        || algorithm != authorization.signature_algorithm
    {
        return Err(Ikev2IkeAuthVerificationError::SignatureHashNotAuthorized);
    }
    authorization
        .hash_authorization
        .validate(authorization.selected_hash, authorization.signed_octets)
        .map_err(map_signature_hash_authority_error)?;

    verify_signature_bytes(
        profile,
        key_material,
        authorization.signed_octets,
        authorization.local_public_credential,
        authorization.signature_algorithm,
        signature,
    )
}

fn verify_signature_bytes(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    public_key: &Ikev2SignaturePublicKey,
    algorithm: IkeSignatureAlgorithm,
    signature: &[u8],
) -> Result<(), Ikev2IkeAuthVerificationError> {
    let signed = build_signed_octets(profile.prf(), key_material, signed_octets)?;
    let public_key_spki = encode_public_key_spki(public_key)?;
    with_signature_verification_operation(algorithm, |module| {
        module.verify_signature(algorithm, &public_key_spki, &signed, signature)
    })
    .map_err(map_signature_module_error)
}

fn decode_method14_signature<'a>(
    public_key: &Ikev2SignaturePublicKey,
    auth_data: &'a [u8],
) -> Result<
    (IkeSignatureAlgorithm, &'a [u8], Ikev2SignatureHashAlgorithm),
    Ikev2IkeAuthVerificationError,
> {
    let (algorithm_identifier, signature) = split_rfc7427_auth_data(auth_data)?;
    if signature.is_empty() {
        return Err(Ikev2IkeAuthVerificationError::SignatureEncodingInvalid);
    }

    let signature_hash = signature_hash_for_identifier(algorithm_identifier)?;
    let algorithm = signature_algorithm_for_public_key_and_identifier(
        public_key,
        algorithm_identifier,
        signature_hash,
    )?;
    Ok((algorithm, signature, signature_hash))
}

fn signature_algorithm_for_public_key_and_hash(
    public_key: &Ikev2SignaturePublicKey,
    signature_hash: Ikev2SignatureHashAlgorithm,
) -> Result<IkeSignatureAlgorithm, Ikev2IkeAuthVerificationError> {
    match (public_key, signature_hash) {
        (Ikev2SignaturePublicKey::Rsa(_), Ikev2SignatureHashAlgorithm::Sha2_256) => {
            Ok(IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256)
        }
        (Ikev2SignaturePublicKey::Rsa(_), Ikev2SignatureHashAlgorithm::Sha2_384) => {
            Ok(IkeSignatureAlgorithm::RsaPssSha2_384)
        }
        (Ikev2SignaturePublicKey::Rsa(_), Ikev2SignatureHashAlgorithm::Sha2_512) => {
            Ok(IkeSignatureAlgorithm::RsaPssSha2_512)
        }
        (Ikev2SignaturePublicKey::EcdsaP256(_), Ikev2SignatureHashAlgorithm::Sha2_256) => {
            Ok(IkeSignatureAlgorithm::EcdsaP256Sha2_256)
        }
        (Ikev2SignaturePublicKey::EcdsaP384(_), Ikev2SignatureHashAlgorithm::Sha2_256) => {
            Ok(IkeSignatureAlgorithm::EcdsaP384Sha2_256)
        }
        (Ikev2SignaturePublicKey::EcdsaP384(_), Ikev2SignatureHashAlgorithm::Sha2_384) => {
            Ok(IkeSignatureAlgorithm::EcdsaP384Sha2_384)
        }
        (Ikev2SignaturePublicKey::EcdsaP521(_), Ikev2SignatureHashAlgorithm::Sha2_512) => {
            Ok(IkeSignatureAlgorithm::EcdsaP521Sha2_512)
        }
        (Ikev2SignaturePublicKey::Ed25519(_), Ikev2SignatureHashAlgorithm::Identity) => {
            Ok(IkeSignatureAlgorithm::Ed25519)
        }
        (Ikev2SignaturePublicKey::Ed448(_), Ikev2SignatureHashAlgorithm::Identity) => {
            Ok(IkeSignatureAlgorithm::Ed448)
        }
        _ => Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch),
    }
}

fn signature_algorithm_for_public_key_and_identifier(
    public_key: &Ikev2SignaturePublicKey,
    identifier: &[u8],
    signature_hash: Ikev2SignatureHashAlgorithm,
) -> Result<IkeSignatureAlgorithm, Ikev2IkeAuthVerificationError> {
    let algorithm = match public_key {
        Ikev2SignaturePublicKey::Rsa(_) => {
            if identifier == RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256 {
                IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256
            } else if pss_identifier_matches(
                identifier,
                &RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_256,
            ) {
                IkeSignatureAlgorithm::RsaPssSha2_256
            } else if pss_identifier_matches(
                identifier,
                &RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_384,
            ) {
                IkeSignatureAlgorithm::RsaPssSha2_384
            } else if pss_identifier_matches(
                identifier,
                &RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_512,
            ) {
                IkeSignatureAlgorithm::RsaPssSha2_512
            } else {
                return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch);
            }
        }
        Ikev2SignaturePublicKey::EcdsaP256(_)
        | Ikev2SignaturePublicKey::EcdsaP384(_)
        | Ikev2SignaturePublicKey::EcdsaP521(_)
            if identifier == RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256
                || identifier == RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384
                || identifier == RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_512 =>
        {
            signature_algorithm_for_public_key_and_hash(public_key, signature_hash)?
        }
        Ikev2SignaturePublicKey::Ed25519(_)
            if identifier == RFC8420_ALGORITHM_IDENTIFIER_ED25519 =>
        {
            IkeSignatureAlgorithm::Ed25519
        }
        Ikev2SignaturePublicKey::Ed448(_) if identifier == RFC8420_ALGORITHM_IDENTIFIER_ED448 => {
            IkeSignatureAlgorithm::Ed448
        }
        _ => return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch),
    };
    Ok(algorithm)
}

fn signature_hash_for_algorithm(
    algorithm: IkeSignatureAlgorithm,
) -> Result<Ikev2SignatureHashAlgorithm, Ikev2IkeAuthVerificationError> {
    match algorithm {
        IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256
        | IkeSignatureAlgorithm::RsaPssSha2_256
        | IkeSignatureAlgorithm::EcdsaP256Sha2_256
        | IkeSignatureAlgorithm::EcdsaP384Sha2_256 => Ok(Ikev2SignatureHashAlgorithm::Sha2_256),
        IkeSignatureAlgorithm::EcdsaP384Sha2_384 | IkeSignatureAlgorithm::RsaPssSha2_384 => {
            Ok(Ikev2SignatureHashAlgorithm::Sha2_384)
        }
        IkeSignatureAlgorithm::EcdsaP521Sha2_512 | IkeSignatureAlgorithm::RsaPssSha2_512 => {
            Ok(Ikev2SignatureHashAlgorithm::Sha2_512)
        }
        IkeSignatureAlgorithm::Ed25519 | IkeSignatureAlgorithm::Ed448 => {
            Ok(Ikev2SignatureHashAlgorithm::Identity)
        }
        _ => Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported),
    }
}

fn signature_identifier(
    algorithm: IkeSignatureAlgorithm,
) -> Result<&'static [u8], Ikev2IkeAuthVerificationError> {
    match algorithm {
        IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256 => {
            Ok(&RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256)
        }
        IkeSignatureAlgorithm::RsaPssSha2_256 => Ok(&RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_256),
        IkeSignatureAlgorithm::RsaPssSha2_384 => Ok(&RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_384),
        IkeSignatureAlgorithm::RsaPssSha2_512 => Ok(&RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_512),
        IkeSignatureAlgorithm::EcdsaP256Sha2_256 | IkeSignatureAlgorithm::EcdsaP384Sha2_256 => {
            Ok(&RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256)
        }
        IkeSignatureAlgorithm::EcdsaP384Sha2_384 => {
            Ok(&RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384)
        }
        IkeSignatureAlgorithm::EcdsaP521Sha2_512 => {
            Ok(&RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_512)
        }
        IkeSignatureAlgorithm::Ed25519 => Ok(&RFC8420_ALGORITHM_IDENTIFIER_ED25519),
        IkeSignatureAlgorithm::Ed448 => Ok(&RFC8420_ALGORITHM_IDENTIFIER_ED448),
        _ => Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported),
    }
}

fn signature_hash_for_identifier(
    identifier: &[u8],
) -> Result<Ikev2SignatureHashAlgorithm, Ikev2IkeAuthVerificationError> {
    if identifier == RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256
        || identifier == RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256
        || pss_identifier_matches(identifier, &RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_256)
    {
        Ok(Ikev2SignatureHashAlgorithm::Sha2_256)
    } else if identifier == RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384
        || pss_identifier_matches(identifier, &RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_384)
    {
        Ok(Ikev2SignatureHashAlgorithm::Sha2_384)
    } else if identifier == RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_512
        || pss_identifier_matches(identifier, &RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_512)
    {
        Ok(Ikev2SignatureHashAlgorithm::Sha2_512)
    } else if identifier == RFC8420_ALGORITHM_IDENTIFIER_ED25519
        || identifier == RFC8420_ALGORITHM_IDENTIFIER_ED448
    {
        Ok(Ikev2SignatureHashAlgorithm::Identity)
    } else {
        Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported)
    }
}

fn pss_identifier_matches(identifier: &[u8], canonical: &[u8; 67]) -> bool {
    let Some(mut actual) = parse_pss_parameters(identifier) else {
        return false;
    };
    let Some(mut expected) = parse_pss_parameters(canonical) else {
        return false;
    };
    // RFC 4055 permits SHA-2 AlgorithmIdentifiers with absent or NULL
    // parameters, including the MGF1 digest. No other parameters are allowed.
    normalize_pss_hash_parameters(&mut actual)
        && normalize_pss_hash_parameters(&mut expected)
        && actual == expected
}

fn parse_pss_parameters(identifier: &[u8]) -> Option<rsa::pkcs1::RsaPssParams<'_>> {
    let identifier = rsa::pkcs8::spki::AlgorithmIdentifierRef::from_der(identifier).ok()?;
    if identifier.oid.as_bytes() != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a] {
        return None;
    }
    let encoded = identifier.parameters?;
    let parameters = encoded.decode_as::<rsa::pkcs1::RsaPssParams<'_>>().ok()?;
    let original = encoded.to_der().ok()?;
    let canonical = parameters.to_der().ok()?;
    // Reject duplicate, unknown, reordered, or trailing parameter fields even
    // if an extensible ASN.1 reader can skip them. The RFC 7427 A.4.3 example
    // also permits one explicit default trailerField after the other fields.
    let canonical_length = canonical.len();
    let explicit_trailer = original.len() == canonical_length + 5
        && (2..128).contains(&canonical_length)
        && original[0] == 0x30
        && original[1] == canonical[1] + 5
        && original[2..canonical_length] == canonical[2..]
        && original[canonical_length..] == [0xa3, 3, 2, 1, 1];
    if original != canonical && !explicit_trailer {
        return None;
    }
    Some(parameters)
}

fn normalize_pss_hash_parameters(parameters: &mut rsa::pkcs1::RsaPssParams<'_>) -> bool {
    if parameters
        .hash
        .parameters
        .is_some_and(|value| !value.is_null())
    {
        return false;
    }
    let Some(mask_hash) = parameters.mask_gen.parameters.as_mut() else {
        return false;
    };
    if mask_hash.parameters.is_some_and(|value| !value.is_null()) {
        return false;
    }
    parameters.hash.parameters = None;
    mask_hash.parameters = None;
    true
}

const fn legacy_ecdsa_algorithm(method: u8) -> Option<IkeSignatureAlgorithm> {
    match method {
        IKEV2_AUTH_METHOD_ECDSA_SHA2_256 => Some(IkeSignatureAlgorithm::EcdsaP256Sha2_256),
        IKEV2_AUTH_METHOD_ECDSA_SHA2_384 => Some(IkeSignatureAlgorithm::EcdsaP384Sha2_384),
        IKEV2_AUTH_METHOD_ECDSA_SHA2_512 => Some(IkeSignatureAlgorithm::EcdsaP521Sha2_512),
        _ => None,
    }
}

fn ecdsa_signature_to_der(
    algorithm: IkeSignatureAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, Ikev2IkeAuthVerificationError> {
    match algorithm {
        IkeSignatureAlgorithm::EcdsaP256Sha2_256 => {
            p256::ecdsa::Signature::from_slice(signature).map(|s| s.to_der().as_bytes().to_vec())
        }
        IkeSignatureAlgorithm::EcdsaP384Sha2_384 => {
            p384::ecdsa::Signature::from_slice(signature).map(|s| s.to_der().as_bytes().to_vec())
        }
        IkeSignatureAlgorithm::EcdsaP521Sha2_512 => {
            p521::ecdsa::Signature::from_slice(signature).map(|s| s.to_der().as_bytes().to_vec())
        }
        _ => return Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported),
    }
    .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)
}

fn ecdsa_signature_to_fixed(
    algorithm: IkeSignatureAlgorithm,
    signature: &[u8],
) -> Result<Vec<u8>, Ikev2IkeAuthVerificationError> {
    match algorithm {
        IkeSignatureAlgorithm::EcdsaP256Sha2_256 => {
            p256::ecdsa::Signature::from_der(signature).map(|s| s.to_bytes().to_vec())
        }
        IkeSignatureAlgorithm::EcdsaP384Sha2_384 => {
            p384::ecdsa::Signature::from_der(signature).map(|s| s.to_bytes().to_vec())
        }
        IkeSignatureAlgorithm::EcdsaP521Sha2_512 => {
            p521::ecdsa::Signature::from_der(signature).map(|s| s.to_bytes().to_vec())
        }
        _ => return Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported),
    }
    .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)
}

fn require_signing_hash_authority(
    authorization: Option<Ikev2SignatureHashSigningAuthorization<'_>>,
    required: Ikev2SignatureHashAlgorithm,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
) -> Result<(), Ikev2IkeAuthVerificationError> {
    let authorization =
        authorization.ok_or(Ikev2IkeAuthVerificationError::SignatureHashAuthorityMissing)?;
    authorization
        .validate(required, signed_octets)
        .map_err(map_signature_hash_authority_error)
}

fn require_verification_hash_authority(
    authorization: Option<Ikev2SignatureHashVerificationAuthorization<'_>>,
    required: Ikev2SignatureHashAlgorithm,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
) -> Result<(), Ikev2IkeAuthVerificationError> {
    let authorization =
        authorization.ok_or(Ikev2IkeAuthVerificationError::SignatureHashAuthorityMissing)?;
    authorization
        .validate(required, signed_octets)
        .map_err(map_signature_hash_authority_error)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod rfc4754_encoding_tests {
    use super::*;

    #[test]
    fn published_rfc4754_vectors_verify_all_three_raw_signature_widths() {
        use opc_crypto_provider::IkeSignatureOperations;
        let cases = [
            (
                9,
                Ikev2SignaturePublicKey::EcdsaP256(
                    p256::ecdsa::VerifyingKey::from_sec1_bytes(include_bytes!(
                        "../tests/data/rfc4754_p256_public.bin"
                    ))
                    .unwrap(),
                ),
                include_bytes!("../tests/data/rfc4754_p256_signature.bin").as_slice(),
                IkeSignatureAlgorithm::EcdsaP256Sha2_256,
            ),
            (
                10,
                Ikev2SignaturePublicKey::EcdsaP384(
                    p384::ecdsa::VerifyingKey::from_sec1_bytes(include_bytes!(
                        "../tests/data/rfc4754_p384_public.bin"
                    ))
                    .unwrap(),
                ),
                include_bytes!("../tests/data/rfc4754_p384_signature.bin").as_slice(),
                IkeSignatureAlgorithm::EcdsaP384Sha2_384,
            ),
            (
                11,
                Ikev2SignaturePublicKey::EcdsaP521(
                    p521::ecdsa::VerifyingKey::from_sec1_bytes(include_bytes!(
                        "../tests/data/rfc4754_p521_public.bin"
                    ))
                    .unwrap(),
                ),
                include_bytes!("../tests/data/rfc4754_p521_signature.bin").as_slice(),
                IkeSignatureAlgorithm::EcdsaP521Sha2_512,
            ),
        ];
        for (method, public, raw, algorithm) in cases {
            let der = ecdsa_signature_to_der(legacy_ecdsa_algorithm(method).unwrap(), raw).unwrap();
            assert_eq!(
                ecdsa_signature_to_fixed(legacy_ecdsa_algorithm(method).unwrap(), &der).unwrap(),
                raw
            );
            let spki = encode_public_key_spki(&public).unwrap();
            crate::Ikev2SoftwareCryptoOperations::new()
                .verify_signature(algorithm, &spki, b"abc", &der)
                .unwrap();
            assert!(crate::Ikev2SoftwareCryptoOperations::new()
                .verify_signature(algorithm, &spki, b"abd", &der)
                .is_err());
        }
    }

    #[test]
    fn pss_identifiers_match_rfc7427_and_rustcrypto_parameters() {
        use rsa::pkcs1::RsaPssParams;
        use rsa::pkcs8::{
            der::{asn1::ObjectIdentifier, Encode},
            spki::AlgorithmIdentifier,
        };
        for (algorithm, identifier, parameters) in [
            (
                IkeSignatureAlgorithm::RsaPssSha2_256,
                RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_256,
                RsaPssParams::new::<rsa::sha2::Sha256>(32),
            ),
            (
                IkeSignatureAlgorithm::RsaPssSha2_384,
                RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_384,
                RsaPssParams::new::<rsa::sha2::Sha384>(48),
            ),
            (
                IkeSignatureAlgorithm::RsaPssSha2_512,
                RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_512,
                RsaPssParams::new::<rsa::sha2::Sha512>(64),
            ),
        ] {
            let independent = AlgorithmIdentifier {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
                parameters: Some(parameters.clone()),
            }
            .to_der()
            .unwrap();
            assert_eq!(identifier.as_slice(), independent);
            assert_eq!(decode_pss_identifier(&identifier), Some(algorithm));
            let mut absent = parameters;
            absent.hash.parameters = None;
            absent.mask_gen.parameters.as_mut().unwrap().parameters = None;
            let absent = AlgorithmIdentifier {
                oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10"),
                parameters: Some(absent),
            }
            .to_der()
            .unwrap();
            assert_eq!(decode_pss_identifier(&absent), Some(algorithm));
            // Reject the extra context wrapper present in the original candidate.
            let mut malformed_mgf = identifier.to_vec();
            malformed_mgf.splice(47..47, [0xa0, 0x0f]);
            for length in [1, 14, 33, 35] {
                malformed_mgf[length] += 2;
            }
            assert_eq!(decode_pss_identifier(&malformed_mgf), None);
            let mut bad_salt = identifier;
            bad_salt[66] = 20;
            assert_eq!(decode_pss_identifier(&bad_salt), None);
            let mut wrong_mgf = identifier;
            wrong_mgf[46] = 7;
            assert_eq!(decode_pss_identifier(&wrong_mgf), None);
            let mut trailing = identifier.to_vec();
            trailing.push(0);
            assert_eq!(decode_pss_identifier(&trailing), None);
        }
        // RFC 7427 Appendix A.4.3 includes explicit trailerField = 1.
        let rfc = [
            0x30, 0x46, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30,
            0x39, 0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
            0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
            0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
            0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20, 0xa3, 0x03, 0x02,
            0x01, 0x01,
        ];
        assert_eq!(
            decode_pss_identifier(&rfc),
            Some(IkeSignatureAlgorithm::RsaPssSha2_256)
        );
        let mut wrong_trailer = rfc;
        wrong_trailer[71] = 2;
        assert_eq!(decode_pss_identifier(&wrong_trailer), None);
    }

    fn decode_pss_identifier(identifier: &[u8]) -> Option<IkeSignatureAlgorithm> {
        [
            (
                IkeSignatureAlgorithm::RsaPssSha2_256,
                RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_256,
            ),
            (
                IkeSignatureAlgorithm::RsaPssSha2_384,
                RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_384,
            ),
            (
                IkeSignatureAlgorithm::RsaPssSha2_512,
                RFC7427_ALGORITHM_IDENTIFIER_RSA_PSS_SHA2_512,
            ),
        ]
        .into_iter()
        .find_map(|(algorithm, canonical)| {
            pss_identifier_matches(identifier, &canonical).then_some(algorithm)
        })
    }

    #[test]
    fn p521_raw_to_der_and_back_is_exact() {
        let mut raw = vec![0_u8; 132];
        raw[65] = 1;
        raw[131] = 2;
        let der = ecdsa_signature_to_der(legacy_ecdsa_algorithm(11).unwrap(), &raw).unwrap();
        assert_eq!(der, vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
        assert_eq!(
            ecdsa_signature_to_fixed(legacy_ecdsa_algorithm(11).unwrap(), &der).unwrap(),
            raw
        );
    }

    #[test]
    fn p256_raw_to_der_handles_high_bit_scalars() {
        let mut raw = vec![0_u8; 64];
        raw[31] = 0x80;
        raw[63] = 0x7f;
        let der = ecdsa_signature_to_der(legacy_ecdsa_algorithm(9).unwrap(), &raw).unwrap();
        assert_eq!(
            der,
            vec![0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x7f]
        );
        assert_eq!(
            ecdsa_signature_to_fixed(legacy_ecdsa_algorithm(9).unwrap(), &der).unwrap(),
            raw
        );
    }

    #[test]
    fn real_p521_der_signature_roundtrips_through_raw_rs() {
        use p521::ecdsa::signature::hazmat::PrehashSigner;
        use p521::pkcs8::DecodePrivateKey;
        use sha2::{Digest, Sha512};

        let der_bytes = include_bytes!("../tests/data/p521_pkcs8.der");
        let signing_key = p521::ecdsa::SigningKey::from_pkcs8_der(der_bytes).expect("P-521 key");
        let message = b"rfc4754-p521-roundtrip";
        let digest = Sha512::digest(message);
        let signature: p521::ecdsa::Signature = signing_key.sign_prehash(&digest).expect("sign");
        let der = signature.to_der();
        let raw = ecdsa_signature_to_fixed(legacy_ecdsa_algorithm(11).unwrap(), der.as_bytes())
            .expect("der to raw");
        assert_eq!(raw.len(), 132);
        let roundtrip =
            ecdsa_signature_to_der(legacy_ecdsa_algorithm(11).unwrap(), &raw).expect("raw to der");
        p521::ecdsa::Signature::from_der(&roundtrip).expect("roundtripped DER parses");
    }

    #[test]
    fn wrong_width_and_non_minimal_der_fail_closed() {
        assert_eq!(
            ecdsa_signature_to_der(legacy_ecdsa_algorithm(9).unwrap(), &[0_u8; 63]),
            Err(Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)
        );
        assert_eq!(
            ecdsa_signature_to_fixed(
                legacy_ecdsa_algorithm(9).unwrap(),
                &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]
            ),
            Err(Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)
        );
    }

    #[test]
    fn ecdsa_der_rejects_an_unnecessary_integer_sign_octet() {
        // Nonzero scalars are valid; only the redundant 00 makes this non-DER.
        let nonminimal = [0x30, 0x07, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x01];
        for method in [9, 10, 11] {
            assert_eq!(
                ecdsa_signature_to_fixed(legacy_ecdsa_algorithm(method).unwrap(), &nonminimal),
                Err(Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)
            );
            let minimal = [0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x01];
            assert!(
                ecdsa_signature_to_fixed(legacy_ecdsa_algorithm(method).unwrap(), &minimal).is_ok()
            );
        }
    }
}

const fn map_signature_hash_authority_error(
    error: Ikev2SignatureHashAuthorityError,
) -> Ikev2IkeAuthVerificationError {
    match error {
        Ikev2SignatureHashAuthorityError::AlgorithmNotAuthorized => {
            Ikev2IkeAuthVerificationError::SignatureHashNotAuthorized
        }
        Ikev2SignatureHashAuthorityError::ExchangeMismatch => {
            Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch
        }
    }
}

fn encode_public_key_spki(
    public_key: &Ikev2SignaturePublicKey,
) -> Result<Vec<u8>, Ikev2IkeAuthVerificationError> {
    match public_key {
        Ikev2SignaturePublicKey::Rsa(public) => public
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid),
        Ikev2SignaturePublicKey::EcdsaP256(public) => public
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid),
        Ikev2SignaturePublicKey::EcdsaP384(public) => public
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid),
        Ikev2SignaturePublicKey::EcdsaP521(public) => public
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid),
        Ikev2SignaturePublicKey::Ed25519(public) => public
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid),
        Ikev2SignaturePublicKey::Ed448(public) => public
            .to_public_key_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid),
    }
}

fn map_signature_module_error(error: Ikev2CryptoModuleError) -> Ikev2IkeAuthVerificationError {
    match error.operation_code() {
        Some(CryptoOperationErrorCode::SignatureEncodingInvalid) => {
            Ikev2IkeAuthVerificationError::SignatureEncodingInvalid
        }
        Some(CryptoOperationErrorCode::SignatureKeyMismatch) => {
            Ikev2IkeAuthVerificationError::SignatureKeyMismatch
        }
        Some(CryptoOperationErrorCode::SignatureComputationFailed) => {
            Ikev2IkeAuthVerificationError::SignatureComputationFailed
        }
        Some(CryptoOperationErrorCode::SignatureVerificationFailed) => {
            Ikev2IkeAuthVerificationError::SignatureVerificationFailed
        }
        _ => Ikev2IkeAuthVerificationError::CryptoModuleFailure { error },
    }
}

/// Split RFC 7427 AUTH data into `(AlgorithmIdentifier, signature)`.
fn split_rfc7427_auth_data(
    auth_data: &[u8],
) -> Result<(&[u8], &[u8]), Ikev2IkeAuthVerificationError> {
    let (&algorithm_identifier_len, rest) = auth_data
        .split_first()
        .ok_or(Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)?;
    let algorithm_identifier_len = usize::from(algorithm_identifier_len);
    if algorithm_identifier_len == 0 || rest.len() < algorithm_identifier_len {
        return Err(Ikev2IkeAuthVerificationError::SignatureEncodingInvalid);
    }
    Ok(rest.split_at(algorithm_identifier_len))
}

#[cfg(feature = "rsa-signing")]
pub(crate) fn rsa_pkcs1v15_sha256_sign(
    private: &RsaPrivateKey,
    signed_octets: &[u8],
) -> Result<Vec<u8>, Ikev2IkeAuthVerificationError> {
    let digest = Sha256::digest(signed_octets);
    private
        .sign_with_rng(
            &mut rsa::rand_core::OsRng,
            Pkcs1v15Sign::new::<Sha256>(),
            &digest,
        )
        .map_err(|_| Ikev2IkeAuthVerificationError::SignatureComputationFailed)
}

pub(crate) fn rsa_pkcs1v15_sha256_verify(
    public: &RsaPublicKey,
    signed_octets: &[u8],
    signature: &[u8],
) -> Result<(), Ikev2IkeAuthVerificationError> {
    let digest = Sha256::digest(signed_octets);
    public
        .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
        .map_err(|_| Ikev2IkeAuthVerificationError::SignatureVerificationFailed)
}

fn rsa_pss_parameters(
    algorithm: IkeSignatureAlgorithm,
    message: &[u8],
) -> Result<(Pss, Vec<u8>), Ikev2IkeAuthVerificationError> {
    match algorithm {
        IkeSignatureAlgorithm::RsaPssSha2_256 => Ok((
            Pss::new_blinded_with_salt::<Sha256>(32),
            Sha256::digest(message).to_vec(),
        )),
        IkeSignatureAlgorithm::RsaPssSha2_384 => Ok((
            Pss::new_blinded_with_salt::<Sha384>(48),
            Sha384::digest(message).to_vec(),
        )),
        IkeSignatureAlgorithm::RsaPssSha2_512 => Ok((
            Pss::new_blinded_with_salt::<Sha512>(64),
            Sha512::digest(message).to_vec(),
        )),
        _ => Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported),
    }
}

pub(crate) fn rsa_pss_verify(
    public: &RsaPublicKey,
    algorithm: IkeSignatureAlgorithm,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Ikev2IkeAuthVerificationError> {
    let (padding, digest) = rsa_pss_parameters(algorithm, message)?;
    public
        .verify(padding, &digest, signature)
        .map_err(|_| Ikev2IkeAuthVerificationError::SignatureVerificationFailed)
}

#[cfg(feature = "rsa-signing")]
pub(crate) fn rsa_pss_sign(
    private: &RsaPrivateKey,
    algorithm: IkeSignatureAlgorithm,
    message: &[u8],
) -> Result<Vec<u8>, Ikev2IkeAuthVerificationError> {
    let (padding, digest) = rsa_pss_parameters(algorithm, message)?;
    private
        .sign_with_rng(&mut rsa::rand_core::OsRng, padding, &digest)
        .map_err(|_| Ikev2IkeAuthVerificationError::SignatureComputationFailed)
}

/// Error returned while loading signature AUTH keys or certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SignatureKeyError {
    /// PKCS#8 DER was not a valid RSA private key.
    RsaPrivateKeyParse,
    /// PKCS#8 DER was not a valid ECDSA private key for the requested curve.
    EcdsaPrivateKeyParse,
    /// PKCS#8 DER was not a valid EdDSA private key of the selected kind.
    EdDsaPrivateKeyParse,
    /// The requested signing method, hash, or key combination is unsupported.
    UnsupportedSignatureAlgorithm,
    /// SubjectPublicKeyInfo DER was malformed.
    SpkiParse,
    /// SubjectPublicKeyInfo DER contained bytes after the parsed value.
    SpkiTrailingData,
    /// X.509 certificate DER was malformed.
    CertificateParse,
    /// X.509 certificate DER contained bytes after the parsed value.
    CertificateTrailingData,
    /// SPKI DER was not a valid RSA public key.
    RsaPublicKeyParse,
    /// SPKI point was not a valid ECDSA public key for its named curve.
    EcdsaPublicKeyParse,
    /// SPKI was not a valid EdDSA public key of the selected kind.
    EdDsaPublicKeyParse,
    /// SPKI algorithm is not a supported RSA, ECDSA, or EdDSA algorithm.
    UnsupportedPublicKeyAlgorithm,
    /// id-ecPublicKey named curve is not P-256, P-384, or P-521.
    UnsupportedEcCurve,
    /// The admitted process crypto module was absent, withdrawn, or failed.
    CryptoModuleFailure {
        /// Stable, redaction-safe module boundary error.
        error: Ikev2CryptoModuleError,
    },
}

impl Ikev2SignatureKeyError {
    /// Stable machine-readable error code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RsaPrivateKeyParse => "ike_auth_signature_rsa_private_key_parse",
            Self::EcdsaPrivateKeyParse => "ike_auth_signature_ecdsa_private_key_parse",
            Self::EdDsaPrivateKeyParse => "ike_auth_signature_eddsa_private_key_parse",
            Self::EdDsaPublicKeyParse => "ike_auth_signature_eddsa_public_key_parse",
            Self::UnsupportedSignatureAlgorithm => "ike_auth_signature_unsupported_algorithm",
            Self::SpkiParse => "ike_auth_signature_spki_parse",
            Self::SpkiTrailingData => "ike_auth_signature_spki_trailing_data",
            Self::CertificateParse => "ike_auth_signature_certificate_parse",
            Self::CertificateTrailingData => "ike_auth_signature_certificate_trailing_data",
            Self::RsaPublicKeyParse => "ike_auth_signature_rsa_public_key_parse",
            Self::EcdsaPublicKeyParse => "ike_auth_signature_ecdsa_public_key_parse",
            Self::UnsupportedPublicKeyAlgorithm => {
                "ike_auth_signature_unsupported_public_key_algorithm"
            }
            Self::UnsupportedEcCurve => "ike_auth_signature_unsupported_ec_curve",
            Self::CryptoModuleFailure { .. } => "ike_auth_signature_crypto_module_failure",
        }
    }
}

impl fmt::Display for Ikev2SignatureKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2SignatureKeyError {}
