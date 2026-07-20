//! RFC 7296 CERTREQ Certification Authority identifiers.
//!
//! This module hashes one exact DER-encoded X.509 `SubjectPublicKeyInfo`
//! element through the process-wide admitted IKEv2 cryptographic module. It
//! does not parse certificates, select trust anchors, or make certificate
//! policy decisions.
//!
//! @spec IETF RFC7296 3.7
//! @req REQ-IETF-RFC7296-CERTREQ-AUTHORITY-HASH-001

use std::{error::Error, fmt};

use spki::{
    der::{Decode, Reader, SliceReader},
    SubjectPublicKeyInfoRef,
};

use crate::crypto_module::{execute_certreq_authority_hash, Ikev2CryptoModuleError};

/// Length in octets of one RFC 7296 CERTREQ Certification Authority hash.
pub const IKEV2_CERTREQ_AUTHORITY_HASH_LEN: usize = 20;

/// Maximum accepted DER `SubjectPublicKeyInfo` input length.
///
/// This 65,535-octet ceiling is an SDK resource bound for parsing and provider
/// dispatch, not an IKEv2 wire-field capacity: only the resulting 20-octet
/// authority identifier is carried in CERTREQ. Validation happens before the
/// admitted module is selected or invoked.
pub const IKEV2_CERTREQ_SUBJECT_PUBLIC_KEY_INFO_MAX_LEN: usize = u16::MAX as usize;

/// Exact DER-encoded X.509 `SubjectPublicKeyInfo` bytes for one trust anchor.
///
/// RFC 7296 section 3.7 hashes the complete DER `SubjectPublicKeyInfo`
/// element, including its algorithm identifier and BIT STRING wrapper. Do not
/// pass a whole certificate, a bare `subjectPublicKey` BIT STRING value, PEM,
/// or a textual key representation.
///
/// `Debug` reports only the bounded byte length.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2CertReqSubjectPublicKeyInfo<'a> {
    der: &'a [u8],
}

impl<'a> Ikev2CertReqSubjectPublicKeyInfo<'a> {
    /// Validate and borrow exactly one DER `SubjectPublicKeyInfo` element.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2CertReqSubjectPublicKeyInfoError`] when the input is
    /// empty, exceeds [`IKEV2_CERTREQ_SUBJECT_PUBLIC_KEY_INFO_MAX_LEN`], is
    /// malformed DER, contains unconsumed elements inside the outer SPKI or
    /// nested `AlgorithmIdentifier` sequence, or contains bytes after the
    /// single SPKI value.
    pub fn from_der(der: &'a [u8]) -> Result<Self, Ikev2CertReqSubjectPublicKeyInfoError> {
        if der.is_empty() {
            return Err(Ikev2CertReqSubjectPublicKeyInfoError::Empty);
        }
        if der.len() > IKEV2_CERTREQ_SUBJECT_PUBLIC_KEY_INFO_MAX_LEN {
            return Err(Ikev2CertReqSubjectPublicKeyInfoError::TooLong);
        }
        let mut reader = SliceReader::new(der)
            .map_err(|_| Ikev2CertReqSubjectPublicKeyInfoError::MalformedDer)?;
        SubjectPublicKeyInfoRef::decode(&mut reader)
            .map_err(|_| Ikev2CertReqSubjectPublicKeyInfoError::MalformedDer)?;
        if !reader.is_finished() {
            return Err(Ikev2CertReqSubjectPublicKeyInfoError::TrailingData);
        }
        Ok(Self { der })
    }

    fn as_der(self) -> &'a [u8] {
        self.der
    }

    /// Return the validated DER length without exposing bytes through
    /// formatting surfaces.
    #[must_use]
    pub const fn len(self) -> usize {
        self.der.len()
    }

    /// Return whether the validated input is empty.
    ///
    /// A successfully constructed value is never empty; this accessor exists
    /// to make the invariant explicit to generic collection code.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.der.is_empty()
    }
}

impl fmt::Debug for Ikev2CertReqSubjectPublicKeyInfo<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ikev2CertReqSubjectPublicKeyInfo")
            .field("der_len", &self.der.len())
            .finish()
    }
}

/// Stable fail-closed validation error for CERTREQ SPKI input.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2CertReqSubjectPublicKeyInfoError {
    /// The DER input was empty.
    Empty,
    /// The DER input exceeded the public bounded-input contract.
    TooLong,
    /// The input was not one valid DER `SubjectPublicKeyInfo` value.
    MalformedDer,
    /// Bytes followed the parsed DER `SubjectPublicKeyInfo` value.
    TrailingData,
}

impl Ikev2CertReqSubjectPublicKeyInfoError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "ike_certreq_spki_empty",
            Self::TooLong => "ike_certreq_spki_too_long",
            Self::MalformedDer => "ike_certreq_spki_malformed_der",
            Self::TrailingData => "ike_certreq_spki_trailing_data",
        }
    }
}

impl fmt::Display for Ikev2CertReqSubjectPublicKeyInfoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for Ikev2CertReqSubjectPublicKeyInfoError {}

/// One RFC 7296 CERTREQ Certification Authority identifier.
///
/// `Debug` reports only the fixed width and never formats the hash bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ikev2CertReqAuthorityHash([u8; IKEV2_CERTREQ_AUTHORITY_HASH_LEN]);

impl Ikev2CertReqAuthorityHash {
    /// Borrow the 20-octet value for concatenation into a CERTREQ
    /// Certification Authority field.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; IKEV2_CERTREQ_AUTHORITY_HASH_LEN] {
        &self.0
    }

    /// Consume the redaction-safe wrapper and return the 20-octet value.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; IKEV2_CERTREQ_AUTHORITY_HASH_LEN] {
        self.0
    }
}

impl fmt::Debug for Ikev2CertReqAuthorityHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ikev2CertReqAuthorityHash")
            .field("len", &IKEV2_CERTREQ_AUTHORITY_HASH_LEN)
            .finish()
    }
}

/// Compute one RFC 7296 section 3.7 CERTREQ Certification Authority hash.
///
/// The operation hashes the complete validated DER `SubjectPublicKeyInfo`
/// element with SHA-1 through the installed
/// [`opc_crypto_provider::IkeCryptoModule`]. It requires an explicit
/// [`crate::Ikev2CryptoRequirements::require_certreq_authority_hash`]
/// requirement; NAT-detection admission alone does not authorize this use.
/// The module's admission evidence, SHA-1 support, and exact 20-octet output
/// are rechecked on every call. There is no software or test fallback.
///
/// # Errors
///
/// Returns [`Ikev2CryptoModuleError`] when no module is installed, CERTREQ
/// hashing was not admitted, module evidence or SHA-1 support changed, the
/// provider failed, or its successful output was not exactly 20 octets.
pub fn ikev2_certreq_authority_key_hash(
    subject_public_key_info: Ikev2CertReqSubjectPublicKeyInfo<'_>,
) -> Result<Ikev2CertReqAuthorityHash, Ikev2CryptoModuleError> {
    let digest = execute_certreq_authority_hash(subject_public_key_info.as_der())?;
    let mut hash = [0_u8; IKEV2_CERTREQ_AUTHORITY_HASH_LEN];
    if digest.len() != hash.len() {
        return Err(Ikev2CryptoModuleError::invalid_output());
    }
    hash.copy_from_slice(&digest);
    Ok(Ikev2CertReqAuthorityHash(hash))
}
