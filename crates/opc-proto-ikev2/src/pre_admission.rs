//! Bounded, non-signing inspection of configured IKEv2 signing material.
//!
//! This module exists only to break the configuration-time dependency cycle
//! between selecting an exact signature-generation requirement and installing
//! the process-wide cryptographic module. Inspection derives public metadata
//! from one configured PKCS#8 value before module admission. It never installs
//! a module, returns a private-key handle, or offers a protocol signing path.
//! Actual private-key loading and every signature operation remain behind the
//! admitted process module.

use std::{error::Error, fmt};

use opc_crypto_provider::IkeSignatureAlgorithm;
use p256::pkcs8::{
    der::{Decode, ErrorKind},
    spki::EncodePublicKey,
    AssociatedOid, ObjectIdentifier, PrivateKeyInfoRef,
};
use subtle::ConstantTimeEq;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Ikev2CryptoRequirements;

const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// Maximum accepted PKCS#8 DER length for pre-admission inspection.
///
/// The supported unencrypted P-256 and P-384 values are much smaller than
/// this conservative bound. It is enforced before any ASN.1 or curve parser
/// runs. PEM and encrypted PKCS#8 are intentionally outside this boundary.
pub const IKEV2_PRE_ADMISSION_PKCS8_DER_MAX_LEN: usize = 4 * 1024;

/// Maximum accepted leaf-certificate DER length for exact SPKI matching.
///
/// The bound is enforced before X.509 parsing. Certificate-chain validation,
/// name checks, validity checks, and key-usage policy remain caller-owned.
pub const IKEV2_PRE_ADMISSION_LEAF_CERTIFICATE_DER_MAX_LEN: usize = 64 * 1024;

/// One exact signature-generation algorithm required at module admission.
///
/// This value contains only an algorithm identifier. It is not a provider
/// admission, private-key handle, signing authority, or protocol fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2SignatureGenerationRequirement {
    algorithm: IkeSignatureAlgorithm,
}

impl Ikev2SignatureGenerationRequirement {
    /// Return the exact signature-generation algorithm.
    #[must_use]
    pub const fn algorithm(self) -> IkeSignatureAlgorithm {
        self.algorithm
    }

    /// Add this generation requirement to process-module startup admission.
    pub fn apply_to(
        self,
        requirements: &mut Ikev2CryptoRequirements,
    ) -> &mut Ikev2CryptoRequirements {
        requirements.require_signature_generation(self.algorithm)
    }
}

impl fmt::Display for Ikev2SignatureGenerationRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.algorithm.as_str())
    }
}

/// Canonical public identity derived from a configured private signing key.
///
/// The identity is the deterministic DER `SubjectPublicKeyInfo` encoding of
/// the public point derived from the private scalar. It retains no PKCS#8
/// input, private scalar, provider object, key handle, or signing authority.
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SignaturePublicKeyIdentity {
    algorithm: IkeSignatureAlgorithm,
    canonical_spki_der: Box<[u8]>,
}

impl Ikev2SignaturePublicKeyIdentity {
    /// Return the signature algorithm associated with this public identity.
    #[must_use]
    pub const fn algorithm(&self) -> IkeSignatureAlgorithm {
        self.algorithm
    }

    /// Return the canonical, exact DER `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn as_spki_der(&self) -> &[u8] {
        &self.canonical_spki_der
    }

    /// Require an exact SPKI match with one complete DER leaf certificate.
    ///
    /// The complete certificate must be one exact bounded DER value. The
    /// comparison uses constant-time byte equality even though SPKI is public,
    /// keeping this security-sensitive identity decision independent of the
    /// first differing byte. This helper performs no certificate-chain,
    /// signature, validity-period, name, or key-usage validation.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2PreAdmissionInspectionError`] when the certificate is
    /// empty, oversized, malformed, has trailing bytes, or its exact SPKI
    /// differs from this identity.
    pub fn require_leaf_certificate_spki_match(
        &self,
        leaf_certificate_der: &[u8],
    ) -> Result<(), Ikev2PreAdmissionInspectionError> {
        if leaf_certificate_der.is_empty() {
            return Err(Ikev2PreAdmissionInspectionError::LeafCertificateEmpty);
        }
        if leaf_certificate_der.len() > IKEV2_PRE_ADMISSION_LEAF_CERTIFICATE_DER_MAX_LEN {
            return Err(Ikev2PreAdmissionInspectionError::LeafCertificateTooLarge);
        }

        let (remainder, certificate) = X509Certificate::from_der(leaf_certificate_der)
            .map_err(|_| Ikev2PreAdmissionInspectionError::LeafCertificateMalformed)?;
        if !remainder.is_empty() {
            return Err(Ikev2PreAdmissionInspectionError::LeafCertificateTrailingData);
        }

        let certificate_spki = certificate.public_key().raw;
        let equal_length = certificate_spki.len() == self.canonical_spki_der.len();
        let equal_bytes =
            equal_length && bool::from(certificate_spki.ct_eq(self.canonical_spki_der.as_ref()));
        if !equal_bytes {
            return Err(Ikev2PreAdmissionInspectionError::LeafCertificateSpkiMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for Ikev2SignaturePublicKeyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ikev2SignaturePublicKeyIdentity")
            .field("algorithm", &self.algorithm.as_str())
            .field("spki_der_len", &self.canonical_spki_der.len())
            .finish()
    }
}

impl fmt::Display for Ikev2SignaturePublicKeyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.algorithm.as_str())
    }
}

/// Public result of non-signing pre-admission PKCS#8 inspection.
///
/// This value deliberately contains only a typed admission requirement and a
/// canonical public identity. It cannot sign:
///
/// ```compile_fail
/// fn cannot_sign(value: opc_proto_ikev2::Ikev2SignatureKeyInspection) {
///     let _signature = value.sign(b"not available");
/// }
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ikev2SignatureKeyInspection {
    requirement: Ikev2SignatureGenerationRequirement,
    public_key_identity: Ikev2SignaturePublicKeyIdentity,
}

impl Ikev2SignatureKeyInspection {
    /// Return the exact process-module signature-generation requirement.
    #[must_use]
    pub const fn requirement(&self) -> Ikev2SignatureGenerationRequirement {
        self.requirement
    }

    /// Return the canonical public identity derived from the private key.
    #[must_use]
    pub const fn public_key_identity(&self) -> &Ikev2SignaturePublicKeyIdentity {
        &self.public_key_identity
    }

    /// Require this key identity to match one complete DER leaf certificate.
    ///
    /// See [`Ikev2SignaturePublicKeyIdentity::require_leaf_certificate_spki_match`]
    /// for the exact trust boundary and caller-owned certificate validation.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2PreAdmissionInspectionError`] for invalid certificate
    /// input or an exact SPKI mismatch.
    pub fn require_leaf_certificate_spki_match(
        &self,
        leaf_certificate_der: &[u8],
    ) -> Result<(), Ikev2PreAdmissionInspectionError> {
        self.public_key_identity
            .require_leaf_certificate_spki_match(leaf_certificate_der)
    }
}

impl fmt::Debug for Ikev2SignatureKeyInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ikev2SignatureKeyInspection")
            .field("requirement", &self.requirement)
            .field("public_key_identity", &self.public_key_identity)
            .finish()
    }
}

impl fmt::Display for Ikev2SignatureKeyInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.requirement.fmt(formatter)
    }
}

/// Inspect one bounded, exact PKCS#8 DER value without module admission.
///
/// Only the SDK's currently supported IKEv2 ECDSA generation profiles are
/// recognized: P-256/SHA-256 and P-384/SHA-384. The borrowed input is never
/// formatted or copied into an ordinary buffer. The RustCrypto secret-key
/// object zeroizes on drop, and the scalar used to derive its public point is
/// held in a separate explicitly zeroizing owner. The returned value retains
/// only public metadata.
///
/// This configuration helper is not a signing or protocol-crypto fallback.
/// Callers must still install a module admitted for the returned requirement,
/// then load and use the real key through that module.
///
/// # Errors
///
/// Returns [`Ikev2PreAdmissionInspectionError`] for empty, oversized,
/// trailing, malformed, unsupported, or non-canonicalizable input.
pub fn inspect_ikev2_signature_key_pkcs8_der(
    pkcs8_der: &[u8],
) -> Result<Ikev2SignatureKeyInspection, Ikev2PreAdmissionInspectionError> {
    if pkcs8_der.is_empty() {
        return Err(Ikev2PreAdmissionInspectionError::Pkcs8Empty);
    }
    if pkcs8_der.len() > IKEV2_PRE_ADMISSION_PKCS8_DER_MAX_LEN {
        return Err(Ikev2PreAdmissionInspectionError::Pkcs8TooLarge);
    }

    let private_key_info = PrivateKeyInfoRef::from_der(pkcs8_der).map_err(|error| {
        if matches!(error.kind(), ErrorKind::TrailingData { .. }) {
            Ikev2PreAdmissionInspectionError::Pkcs8TrailingData
        } else {
            Ikev2PreAdmissionInspectionError::Pkcs8Malformed
        }
    })?;

    if private_key_info.algorithm.oid != OID_EC_PUBLIC_KEY {
        return Err(Ikev2PreAdmissionInspectionError::UnsupportedAlgorithm);
    }
    let curve_oid = private_key_info
        .algorithm
        .parameters_oid()
        .map_err(|_| Ikev2PreAdmissionInspectionError::Pkcs8AlgorithmParametersMalformed)?;

    if curve_oid == p256::NistP256::OID {
        inspect_p256(private_key_info)
    } else if curve_oid == p384::NistP384::OID {
        inspect_p384(private_key_info)
    } else {
        Err(Ikev2PreAdmissionInspectionError::UnsupportedAlgorithm)
    }
}

fn inspect_p256(
    private_key_info: PrivateKeyInfoRef<'_>,
) -> Result<Ikev2SignatureKeyInspection, Ikev2PreAdmissionInspectionError> {
    require_zeroize_on_drop::<p256::SecretKey>();
    require_zeroize::<p256::NonZeroScalar>();
    let secret = p256::SecretKey::try_from(private_key_info)
        .map_err(|_| Ikev2PreAdmissionInspectionError::Pkcs8KeyMalformed)?;
    // Keep the derivation scalar in an explicit zeroizing owner. Calling
    // `SecretKey::public_key()` would create an unbound `NonZeroScalar`
    // temporary whose type does not itself zeroize on drop.
    let secret_scalar = Zeroizing::new(secret.to_nonzero_scalar());
    let public = p256::PublicKey::from_secret_scalar(&secret_scalar);
    let canonical_spki_der = public
        .to_public_key_der()
        .map_err(|_| Ikev2PreAdmissionInspectionError::PublicIdentityEncodingFailed)?
        .into_vec()
        .into_boxed_slice();
    drop(secret_scalar);
    drop(secret);

    Ok(inspection(
        IkeSignatureAlgorithm::EcdsaP256Sha2_256,
        canonical_spki_der,
    ))
}

fn inspect_p384(
    private_key_info: PrivateKeyInfoRef<'_>,
) -> Result<Ikev2SignatureKeyInspection, Ikev2PreAdmissionInspectionError> {
    require_zeroize_on_drop::<p384::SecretKey>();
    require_zeroize::<p384::NonZeroScalar>();
    let secret = p384::SecretKey::try_from(private_key_info)
        .map_err(|_| Ikev2PreAdmissionInspectionError::Pkcs8KeyMalformed)?;
    // See the P-256 path: the explicit owner wipes this otherwise-unowned
    // scalar temporary.
    let secret_scalar = Zeroizing::new(secret.to_nonzero_scalar());
    let public = p384::PublicKey::from_secret_scalar(&secret_scalar);
    let canonical_spki_der = public
        .to_public_key_der()
        .map_err(|_| Ikev2PreAdmissionInspectionError::PublicIdentityEncodingFailed)?
        .into_vec()
        .into_boxed_slice();
    drop(secret_scalar);
    drop(secret);

    Ok(inspection(
        IkeSignatureAlgorithm::EcdsaP384Sha2_384,
        canonical_spki_der,
    ))
}

fn inspection(
    algorithm: IkeSignatureAlgorithm,
    canonical_spki_der: Box<[u8]>,
) -> Ikev2SignatureKeyInspection {
    Ikev2SignatureKeyInspection {
        requirement: Ikev2SignatureGenerationRequirement { algorithm },
        public_key_identity: Ikev2SignaturePublicKeyIdentity {
            algorithm,
            canonical_spki_der,
        },
    }
}

fn require_zeroize_on_drop<T: ZeroizeOnDrop>() {}

fn require_zeroize<T: Zeroize>() {}

/// Stable, redaction-safe pre-admission inspection failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2PreAdmissionInspectionError {
    /// No PKCS#8 DER bytes were supplied.
    Pkcs8Empty,
    /// PKCS#8 DER exceeded [`IKEV2_PRE_ADMISSION_PKCS8_DER_MAX_LEN`].
    Pkcs8TooLarge,
    /// Bytes followed the one complete PKCS#8 DER value.
    Pkcs8TrailingData,
    /// The PKCS#8 ASN.1 structure was malformed.
    Pkcs8Malformed,
    /// The EC AlgorithmIdentifier parameters were missing or malformed.
    Pkcs8AlgorithmParametersMalformed,
    /// The PKCS#8 named a supported curve but contained an invalid key.
    Pkcs8KeyMalformed,
    /// The PKCS#8 algorithm or named curve is not supported by this boundary.
    UnsupportedAlgorithm,
    /// Canonical public SPKI encoding failed.
    PublicIdentityEncodingFailed,
    /// No leaf-certificate DER bytes were supplied.
    LeafCertificateEmpty,
    /// Leaf-certificate DER exceeded
    /// [`IKEV2_PRE_ADMISSION_LEAF_CERTIFICATE_DER_MAX_LEN`].
    LeafCertificateTooLarge,
    /// The leaf-certificate ASN.1 structure was malformed.
    LeafCertificateMalformed,
    /// Bytes followed the one complete leaf-certificate DER value.
    LeafCertificateTrailingData,
    /// The leaf certificate's exact SPKI differs from the derived identity.
    LeafCertificateSpkiMismatch,
}

impl Ikev2PreAdmissionInspectionError {
    /// Return the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pkcs8Empty => "ikev2_pre_admission_pkcs8_empty",
            Self::Pkcs8TooLarge => "ikev2_pre_admission_pkcs8_too_large",
            Self::Pkcs8TrailingData => "ikev2_pre_admission_pkcs8_trailing_data",
            Self::Pkcs8Malformed => "ikev2_pre_admission_pkcs8_malformed",
            Self::Pkcs8AlgorithmParametersMalformed => {
                "ikev2_pre_admission_pkcs8_algorithm_parameters_malformed"
            }
            Self::Pkcs8KeyMalformed => "ikev2_pre_admission_pkcs8_key_malformed",
            Self::UnsupportedAlgorithm => "ikev2_pre_admission_algorithm_unsupported",
            Self::PublicIdentityEncodingFailed => {
                "ikev2_pre_admission_public_identity_encoding_failed"
            }
            Self::LeafCertificateEmpty => "ikev2_pre_admission_leaf_certificate_empty",
            Self::LeafCertificateTooLarge => "ikev2_pre_admission_leaf_certificate_too_large",
            Self::LeafCertificateMalformed => "ikev2_pre_admission_leaf_certificate_malformed",
            Self::LeafCertificateTrailingData => {
                "ikev2_pre_admission_leaf_certificate_trailing_data"
            }
            Self::LeafCertificateSpkiMismatch => {
                "ikev2_pre_admission_leaf_certificate_spki_mismatch"
            }
        }
    }
}

impl fmt::Display for Ikev2PreAdmissionInspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for Ikev2PreAdmissionInspectionError {}
