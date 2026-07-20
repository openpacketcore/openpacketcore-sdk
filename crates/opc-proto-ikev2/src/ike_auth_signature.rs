//! Signature-based IKE_AUTH authentication (methods 1 and 14).
//!
//! These helpers compute and verify the AUTH payload for RSA Digital Signature
//! (method 1, RFC 7296) and Digital Signature (method 14, RFC 7427) over the
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
//! Signing defaults to ECDSA only. RSA *signing* (method 1, and RSA under
//! method 14) is compiled in only with the `rsa-signing` cargo feature, so a
//! default build performs no RSA private-key operations and stays outside the
//! practical scope of RUSTSEC-2023-0071 (Marvin timing sidechannel in the
//! `rsa` crate). RSA *verification* of peer signatures uses public-key
//! operations only and is always available. Deploy ECDSA (P-256/P-384)
//! responder certificates unless a peer population forces RSA.
//!
//! @spec IETF RFC7296 2.15, 3.8; IETF RFC7427
//! @req REQ-IETF-RFC7427-IKE-AUTH-SIGNATURE-001

use std::{error::Error, fmt};

use opc_crypto_provider::{CryptoOperationErrorCode, IkeSignatureAlgorithm, IkeSigningKey};
use p256::pkcs8::EncodePublicKey as EcEncodePublicKey;
#[cfg(feature = "rsa-signing")]
use rsa::RsaPrivateKey;
use rsa::{
    pkcs8::{DecodePublicKey, EncodePublicKey as RsaEncodePublicKey},
    Pkcs1v15Sign, RsaPublicKey,
};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo, X509Certificate};

use crate::{
    crypto_module::{
        execute_signing_key, with_signature_generation_operation,
        with_signature_verification_operation, Ikev2CryptoModuleError,
    },
    ike_auth::{build_signed_octets, validate_signed_octets},
    ike_auth::{
        Ikev2AuthenticationPayload, Ikev2IkeAuthSignedOctets, Ikev2IkeAuthVerificationError,
    },
    sa_init_crypto::{Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial},
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

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_NAMED_CURVE_P256: &str = "1.2.840.10045.3.1.7";
const OID_NAMED_CURVE_P384: &str = "1.3.132.0.34";

/// AUTH method selector for signature-based IKE_AUTH.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SignatureAuthMethod {
    /// Method 1, RSA Digital Signature (RSASSA-PKCS1-v1_5 with SHA-256).
    ///
    /// Signing with this method requires the `rsa-signing` cargo feature.
    #[cfg(feature = "rsa-signing")]
    RsaDigitalSignature,
    /// Method 14, RFC 7427 Digital Signature.
    DigitalSignature,
}

impl Ikev2SignatureAuthMethod {
    /// Return the RFC 7296 AUTH Method octet.
    pub const fn as_u8(self) -> u8 {
        match self {
            #[cfg(feature = "rsa-signing")]
            Self::RsaDigitalSignature => IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE,
            Self::DigitalSignature => IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
        }
    }
}

/// Responder or initiator signing key plus chosen AUTH method.
///
/// Construct through the `rsa_pkcs8_der` / `ecdsa_p256_pkcs8_der` /
/// `ecdsa_p384_pkcs8_der` constructors, which reject method/key combinations
/// that IKEv2 does not allow. The wrapped RustCrypto key types zeroize their
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
}

impl Ikev2SignaturePublicKey {
    /// Parse a DER SubjectPublicKeyInfo into a typed verification key.
    ///
    /// Supports `rsaEncryption`, and `id-ecPublicKey` with the P-256 or P-384
    /// named curve.
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
                    _ => Err(Ikev2SignatureKeyError::UnsupportedEcCurve),
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
                },
            )
            .finish()
    }
}

/// Compute signature AUTH data over the RFC 7296 signed octets.
///
/// For method 1 the returned AUTH data is the raw RSASSA-PKCS1-v1_5 SHA-256
/// signature. For method 14 it is the RFC 7427 framing:
/// `len(AlgorithmIdentifier) || DER(AlgorithmIdentifier) || signature`, where
/// the signature is PKCS#1 v1.5 for RSA and a DER-encoded `ECDSA-Sig-Value`
/// for ECDSA, matching X.509 signature formats as RFC 7427 requires.
///
/// Feed the result into `build_ike_auth_authentication_payload` with
/// `key.method().as_u8()` as the AUTH method.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthVerificationError`] when the transcript inputs are
/// structurally invalid, the method/key combination is not allowed (method 1
/// requires an RSA key), or the signing backend fails.
pub fn compute_ike_auth_signature(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    key: &Ikev2SignatureAuthKey,
) -> Result<Vec<u8>, Ikev2IkeAuthVerificationError> {
    validate_signed_octets(signed_octets)?;
    let signed = build_signed_octets(profile.prf(), key_material, signed_octets)?;
    let signature = execute_signing_key(key.algorithm, key.signing_key.as_ref(), &signed)
        .map_err(map_signature_module_error)?;

    #[cfg(feature = "rsa-signing")]
    if key.method == Ikev2SignatureAuthMethod::RsaDigitalSignature {
        if key.algorithm != IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256 {
            return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch);
        }
        return Ok(signature);
    }

    let algorithm_identifier: &[u8] = match key.algorithm {
        IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256 => &RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256,
        IkeSignatureAlgorithm::EcdsaP256Sha2_256 | IkeSignatureAlgorithm::EcdsaP384Sha2_256 => {
            &RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256
        }
        IkeSignatureAlgorithm::EcdsaP384Sha2_384 => &RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384,
        _ => return Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported),
    };
    let algorithm_identifier_len = u8::try_from(algorithm_identifier.len())
        .map_err(|_| Ikev2IkeAuthVerificationError::SignatureEncodingInvalid)?;
    let mut auth_data = Vec::with_capacity(1 + algorithm_identifier.len() + signature.len());
    auth_data.push(algorithm_identifier_len);
    auth_data.extend_from_slice(algorithm_identifier);
    auth_data.extend_from_slice(&signature);
    Ok(auth_data)
}

/// Verify a signature AUTH payload (method 1 or 14) over the signed octets.
///
/// The supplied public key is the caller's trust decision — a pinned SPKI or a
/// key extracted from a certificate the product layer already validated. Any
/// AUTH method other than 1 or 14 (including the shared-key method 2, which
/// [`crate::verify_ike_auth_shared_key_mic`] owns) fails with
/// `UnsupportedAuthenticationMethod`.
///
/// # Errors
///
/// Returns [`Ikev2IkeAuthVerificationError`] when the transcript inputs are
/// structurally invalid, the AUTH data framing is malformed, the algorithm or
/// method is unsupported, the key type does not match the signature algorithm,
/// or the signature does not verify.
pub fn verify_ike_auth_signature(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &Ikev2SaInitKeyMaterial,
    signed_octets: Ikev2IkeAuthSignedOctets<'_>,
    public_key: &Ikev2SignaturePublicKey,
    authentication: &Ikev2AuthenticationPayload<'_>,
) -> Result<(), Ikev2IkeAuthVerificationError> {
    validate_signed_octets(signed_octets)?;
    let signed = build_signed_octets(profile.prf(), key_material, signed_octets)?;

    let (algorithm, signature) = match authentication.auth_method {
        IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE => match public_key {
            Ikev2SignaturePublicKey::Rsa(_) => (
                IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256,
                authentication.auth_data,
            ),
            _ => return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch),
        },
        IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE => {
            let (algorithm_identifier, signature) =
                split_rfc7427_auth_data(authentication.auth_data)?;
            if signature.is_empty() {
                return Err(Ikev2IkeAuthVerificationError::SignatureEncodingInvalid);
            }
            if algorithm_identifier == RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256 {
                match public_key {
                    Ikev2SignaturePublicKey::Rsa(_) => {
                        (IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256, signature)
                    }
                    _ => return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch),
                }
            } else if algorithm_identifier == RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256 {
                match public_key {
                    Ikev2SignaturePublicKey::EcdsaP256(_) => {
                        (IkeSignatureAlgorithm::EcdsaP256Sha2_256, signature)
                    }
                    Ikev2SignaturePublicKey::EcdsaP384(_) => {
                        (IkeSignatureAlgorithm::EcdsaP384Sha2_256, signature)
                    }
                    Ikev2SignaturePublicKey::Rsa(_) => {
                        return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch);
                    }
                }
            } else if algorithm_identifier == RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384 {
                match public_key {
                    Ikev2SignaturePublicKey::EcdsaP384(_) => {
                        (IkeSignatureAlgorithm::EcdsaP384Sha2_384, signature)
                    }
                    _ => return Err(Ikev2IkeAuthVerificationError::SignatureKeyMismatch),
                }
            } else {
                return Err(Ikev2IkeAuthVerificationError::SignatureAlgorithmUnsupported);
            }
        }
        method => {
            return Err(Ikev2IkeAuthVerificationError::UnsupportedAuthenticationMethod { method });
        }
    };
    let public_key_spki = encode_public_key_spki(public_key)?;
    with_signature_verification_operation(algorithm, |module| {
        module.verify_signature(algorithm, &public_key_spki, &signed, signature)
    })
    .map_err(map_signature_module_error)
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
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
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

/// Error returned while loading signature AUTH keys or certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2SignatureKeyError {
    /// PKCS#8 DER was not a valid RSA private key.
    RsaPrivateKeyParse,
    /// PKCS#8 DER was not a valid ECDSA private key for the requested curve.
    EcdsaPrivateKeyParse,
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
    /// SPKI algorithm is neither rsaEncryption nor id-ecPublicKey.
    UnsupportedPublicKeyAlgorithm,
    /// id-ecPublicKey named curve is not P-256 or P-384.
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
