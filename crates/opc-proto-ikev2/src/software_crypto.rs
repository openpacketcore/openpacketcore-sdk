//! Default software implementation of the `opc-crypto-provider` IKE
//! operation traits.
//!
//! [`Ikev2SoftwareCryptoOperations`] delegates every operation to the
//! algorithm code that already backs this crate's IKEv2 helpers — the same
//! HMAC-SHA2 composition, AES-GCM/AES-CBC primitives, DH/ECDH agreement, and
//! RSA/ECDSA signature calls — so its outputs are byte-identical to the
//! existing code paths. Nothing in this module is wired into those existing
//! paths yet: rerouting the IKEv2 call sites through an admitted provider is
//! a later slice. Secret-bearing outputs use [`zeroize::Zeroizing`], and the
//! opaque [`IkeDhKeyPair`]/[`IkeSigningKey`] handles keep backend-native
//! private-key types out of the provider boundary.
//!
//! @spec IETF RFC7296 2.13-2.14, 3.14; IETF RFC4868 2.6-2.7; IETF RFC5282 3;
//! IETF RFC7427
//! @req REQ-IETF-RFC7296-SA-INIT-CRYPTO-MATERIAL-001

use std::fmt;

use opc_crypto_provider::ops::{
    CryptoOperationError, CryptoOperationErrorCode, IkeAeadAlgorithm, IkeCbcAlgorithm, IkeDhGroup,
    IkeDhKeyPair, IkeDiffieHellmanOperations, IkeEncryptionOperations, IkeIntegrityAlgorithm,
    IkeIntegrityOperations, IkePrfAlgorithm, IkePrfOperations, IkeSignatureAlgorithm,
    IkeSignatureOperations, IkeSigningKey,
};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::pkcs8::DecodePrivateKey;
#[cfg(feature = "rsa-signing")]
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256, Sha384};
use zeroize::Zeroizing;

#[cfg(feature = "rsa-signing")]
use crate::ike_auth_signature::rsa_pkcs1v15_sha256_sign;
use crate::{
    ike_auth_signature::{rsa_pkcs1v15_sha256_verify, Ikev2SignatureKeyError},
    protected_payload_crypto::{
        compute_integrity_checksum, decrypt_aes_cbc_in_place, decrypt_aes_gcm, encrypt_aes_cbc,
        encrypt_aes_gcm, verify_integrity_checksum, Ikev2ProtectedPayloadCryptoError,
        SelectedProtectedPayloadKeys, IKEV2_AES_CBC_IV_LEN, IKEV2_AES_GCM_EXPLICIT_IV_LEN,
    },
    sa_init_crypto::{
        prf, prf_plus, Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2EphemeralDhKey,
        Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm, Ikev2SaInitCryptoError,
    },
    Ikev2SignaturePublicKey,
};

/// Default software provider for the IKE operation traits.
///
/// Every operation delegates to this crate's existing algorithm code, so the
/// outputs are byte-identical to the current IKEv2 helpers. The type holds no
/// state and no key material.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ikev2SoftwareCryptoOperations;

impl Ikev2SoftwareCryptoOperations {
    /// Build the default software operations provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

fn unsupported_algorithm() -> CryptoOperationError {
    CryptoOperationError::new(CryptoOperationErrorCode::UnsupportedAlgorithm)
}

fn invalid_input_length() -> CryptoOperationError {
    CryptoOperationError::new(CryptoOperationErrorCode::InvalidInputLength)
}

fn map_prf_algorithm(
    algorithm: IkePrfAlgorithm,
) -> Result<Ikev2PrfAlgorithm, CryptoOperationError> {
    match algorithm {
        IkePrfAlgorithm::HmacSha2_256 => Ok(Ikev2PrfAlgorithm::HmacSha2_256),
        IkePrfAlgorithm::HmacSha2_384 => Ok(Ikev2PrfAlgorithm::HmacSha2_384),
        IkePrfAlgorithm::HmacSha2_512 => Ok(Ikev2PrfAlgorithm::HmacSha2_512),
        _ => Err(unsupported_algorithm()),
    }
}

fn map_integrity_algorithm(
    algorithm: IkeIntegrityAlgorithm,
) -> Result<Ikev2IntegrityAlgorithm, CryptoOperationError> {
    match algorithm {
        IkeIntegrityAlgorithm::HmacSha2_256_128 => Ok(Ikev2IntegrityAlgorithm::HmacSha2_256_128),
        IkeIntegrityAlgorithm::HmacSha2_384_192 => Ok(Ikev2IntegrityAlgorithm::HmacSha2_384_192),
        IkeIntegrityAlgorithm::HmacSha2_512_256 => Ok(Ikev2IntegrityAlgorithm::HmacSha2_512_256),
        _ => Err(unsupported_algorithm()),
    }
}

fn map_aead_algorithm(
    algorithm: IkeAeadAlgorithm,
) -> Result<Ikev2EncryptionAlgorithm, CryptoOperationError> {
    match algorithm {
        IkeAeadAlgorithm::AesGcm16_128 => Ok(Ikev2EncryptionAlgorithm::AesGcm16_128),
        IkeAeadAlgorithm::AesGcm16_192 => Ok(Ikev2EncryptionAlgorithm::AesGcm16_192),
        IkeAeadAlgorithm::AesGcm16_256 => Ok(Ikev2EncryptionAlgorithm::AesGcm16_256),
        _ => Err(unsupported_algorithm()),
    }
}

fn map_cbc_algorithm(
    algorithm: IkeCbcAlgorithm,
) -> Result<Ikev2EncryptionAlgorithm, CryptoOperationError> {
    match algorithm {
        IkeCbcAlgorithm::AesCbc128 => Ok(Ikev2EncryptionAlgorithm::AesCbc128),
        IkeCbcAlgorithm::AesCbc192 => Ok(Ikev2EncryptionAlgorithm::AesCbc192),
        IkeCbcAlgorithm::AesCbc256 => Ok(Ikev2EncryptionAlgorithm::AesCbc256),
        _ => Err(unsupported_algorithm()),
    }
}

fn map_dh_group(group: IkeDhGroup) -> Result<Ikev2DhGroup, CryptoOperationError> {
    match group {
        IkeDhGroup::Modp2048 => Ok(Ikev2DhGroup::Modp2048),
        IkeDhGroup::Ecp256 => Ok(Ikev2DhGroup::Ecp256),
        IkeDhGroup::Ecp384 => Ok(Ikev2DhGroup::Ecp384),
        IkeDhGroup::Ecp521 => Ok(Ikev2DhGroup::Ecp521),
        _ => Err(unsupported_algorithm()),
    }
}

fn map_sa_init_error(error: Ikev2SaInitCryptoError) -> CryptoOperationError {
    let code = match error {
        Ikev2SaInitCryptoError::InvalidKeyLength { .. } => {
            CryptoOperationErrorCode::InvalidKeyLength
        }
        Ikev2SaInitCryptoError::KeyMaterialLimitOverflow { .. } => {
            CryptoOperationErrorCode::OutputLengthUnsupported
        }
        Ikev2SaInitCryptoError::InvalidPeerPublicKey { .. } => {
            CryptoOperationErrorCode::InvalidPeerPublicKey
        }
        Ikev2SaInitCryptoError::KeyGenerationFailed { .. } => {
            CryptoOperationErrorCode::KeyGenerationFailed
        }
        Ikev2SaInitCryptoError::KeyAgreementFailed { .. } => {
            CryptoOperationErrorCode::KeyAgreementFailed
        }
        _ => CryptoOperationErrorCode::OperationFailed,
    };
    CryptoOperationError::with_source(code, error)
}

fn map_protected_payload_error(error: Ikev2ProtectedPayloadCryptoError) -> CryptoOperationError {
    let code = match error {
        Ikev2ProtectedPayloadCryptoError::InvalidKeyMaterialLength { .. } => {
            CryptoOperationErrorCode::InvalidKeyLength
        }
        Ikev2ProtectedPayloadCryptoError::ProtectedPayloadTooShort { .. }
        | Ikev2ProtectedPayloadCryptoError::InvalidIvLength { .. }
        | Ikev2ProtectedPayloadCryptoError::InvalidCiphertextLength { .. } => {
            CryptoOperationErrorCode::InvalidInputLength
        }
        Ikev2ProtectedPayloadCryptoError::AuthenticationFailed => {
            CryptoOperationErrorCode::AuthenticationFailed
        }
        Ikev2ProtectedPayloadCryptoError::UnsupportedEncryptionProfile { .. } => {
            CryptoOperationErrorCode::UnsupportedAlgorithm
        }
        _ => CryptoOperationErrorCode::OperationFailed,
    };
    CryptoOperationError::with_source(code, error)
}

impl IkePrfOperations for Ikev2SoftwareCryptoOperations {
    fn prf(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        let algorithm = map_prf_algorithm(algorithm)?;
        prf(algorithm, key, data).map_err(map_sa_init_error)
    }

    fn prf_plus(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        seed: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        let algorithm = map_prf_algorithm(algorithm)?;
        prf_plus(algorithm, key, seed, output_len).map_err(map_sa_init_error)
    }
}

impl IkeIntegrityOperations for Ikev2SoftwareCryptoOperations {
    fn compute_integrity_checksum(
        &self,
        algorithm: IkeIntegrityAlgorithm,
        key: &[u8],
        message_prefix: &[u8],
        message_suffix: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        let algorithm = map_integrity_algorithm(algorithm)?;
        compute_integrity_checksum(algorithm, key, message_prefix, message_suffix)
            .map_err(map_protected_payload_error)
    }

    fn verify_integrity_checksum(
        &self,
        algorithm: IkeIntegrityAlgorithm,
        key: &[u8],
        authenticated_message: &[u8],
        received_icv: &[u8],
    ) -> Result<(), CryptoOperationError> {
        let algorithm = map_integrity_algorithm(algorithm)?;
        // Delegates to the existing helper, which compares the truncated
        // checksum with `subtle::ConstantTimeEq` (constant time).
        verify_integrity_checksum(algorithm, key, authenticated_message, received_icv)
            .map_err(map_protected_payload_error)
    }
}

impl IkeEncryptionOperations for Ikev2SoftwareCryptoOperations {
    fn seal_aead(
        &self,
        algorithm: IkeAeadAlgorithm,
        key: &[u8],
        salt: &[u8],
        explicit_iv: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoOperationError> {
        let mapped = map_aead_algorithm(algorithm)?;
        if salt.len() != algorithm.salt_len() {
            return Err(invalid_input_length());
        }
        let explicit_iv: [u8; IKEV2_AES_GCM_EXPLICIT_IV_LEN] =
            explicit_iv.try_into().map_err(|_| invalid_input_length())?;
        let keys = SelectedProtectedPayloadKeys {
            encryption_key: key,
            salt,
            integrity_key: &[],
        };
        encrypt_aes_gcm(mapped, keys, associated_data, plaintext, explicit_iv)
            .map_err(map_protected_payload_error)
    }

    fn open_aead(
        &self,
        algorithm: IkeAeadAlgorithm,
        key: &[u8],
        salt: &[u8],
        associated_data: &[u8],
        protected_body: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        let mapped = map_aead_algorithm(algorithm)?;
        if salt.len() != algorithm.salt_len() {
            return Err(invalid_input_length());
        }
        let keys = SelectedProtectedPayloadKeys {
            encryption_key: key,
            salt,
            integrity_key: &[],
        };
        decrypt_aes_gcm(mapped, keys, associated_data, protected_body)
            .map(Zeroizing::new)
            .map_err(map_protected_payload_error)
    }

    fn encrypt_cbc(
        &self,
        algorithm: IkeCbcAlgorithm,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoOperationError> {
        let mapped = map_cbc_algorithm(algorithm)?;
        if iv.len() != IKEV2_AES_CBC_IV_LEN {
            return Err(invalid_input_length());
        }
        // The zeroizing buffer wipes the copied plaintext if encryption
        // fails; on success it holds only ciphertext.
        let mut buffer = Zeroizing::new(plaintext.to_vec());
        encrypt_aes_cbc(mapped, key, iv, &mut buffer).map_err(map_protected_payload_error)?;
        Ok(buffer.to_vec())
    }

    fn decrypt_cbc(
        &self,
        algorithm: IkeCbcAlgorithm,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        let mapped = map_cbc_algorithm(algorithm)?;
        if iv.len() != IKEV2_AES_CBC_IV_LEN {
            return Err(invalid_input_length());
        }
        // Same empty/alignment guard the existing decrypt path applies
        // before its in-place primitive.
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(algorithm.block_len()) {
            return Err(invalid_input_length());
        }
        let mut buffer = Zeroizing::new(ciphertext.to_vec());
        decrypt_aes_cbc_in_place(mapped, key, iv, &mut buffer)
            .map_err(map_protected_payload_error)?;
        Ok(buffer)
    }
}

impl IkeDiffieHellmanOperations for Ikev2SoftwareCryptoOperations {
    fn generate_keypair(
        &self,
        group: IkeDhGroup,
    ) -> Result<Box<dyn IkeDhKeyPair>, CryptoOperationError> {
        let mapped = map_dh_group(group)?;
        let inner = Ikev2EphemeralDhKey::generate(mapped).map_err(map_sa_init_error)?;
        Ok(Box::new(SoftwareIkeDhKeyPair { group, inner }))
    }
}

/// Opaque wrapper keeping [`Ikev2EphemeralDhKey`]'s backend-native secret
/// enum out of the provider boundary.
struct SoftwareIkeDhKeyPair {
    group: IkeDhGroup,
    inner: Ikev2EphemeralDhKey,
}

impl IkeDhKeyPair for SoftwareIkeDhKeyPair {
    fn group(&self) -> IkeDhGroup {
        self.group
    }

    fn public_value(&self) -> &[u8] {
        self.inner.public_value()
    }

    fn agree(&self, peer_public_value: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.inner
            .agree(peer_public_value)
            .map_err(map_sa_init_error)
    }
}

impl fmt::Debug for SoftwareIkeDhKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareIkeDhKeyPair")
            .field("group", &self.group.as_str())
            .field("public_value_len", &self.inner.public_value().len())
            .finish()
    }
}

impl IkeSignatureOperations for Ikev2SoftwareCryptoOperations {
    fn load_signing_key(
        &self,
        algorithm: IkeSignatureAlgorithm,
        pkcs8_der: &[u8],
    ) -> Result<Box<dyn IkeSigningKey>, CryptoOperationError> {
        match algorithm {
            IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256 => {
                #[cfg(feature = "rsa-signing")]
                {
                    use rsa::pkcs8::DecodePrivateKey as RsaDecodePrivateKey;
                    let key = RsaPrivateKey::from_pkcs8_der(pkcs8_der).map_err(|_| {
                        CryptoOperationError::with_source(
                            CryptoOperationErrorCode::InvalidSigningKey,
                            Ikev2SignatureKeyError::RsaPrivateKeyParse,
                        )
                    })?;
                    Ok(Box::new(SoftwareIkeSigningKey {
                        algorithm,
                        kind: SoftwareSigningKeyKind::Rsa(Box::new(key)),
                    }))
                }
                #[cfg(not(feature = "rsa-signing"))]
                {
                    // Without the `rsa-signing` feature this build compiles no
                    // RSA private-key operation; fail closed instead of
                    // falling back to another code path.
                    let _ = pkcs8_der;
                    Err(unsupported_algorithm())
                }
            }
            IkeSignatureAlgorithm::EcdsaP256Sha2_256 => {
                let key = p256::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der).map_err(|_| {
                    CryptoOperationError::with_source(
                        CryptoOperationErrorCode::InvalidSigningKey,
                        Ikev2SignatureKeyError::EcdsaPrivateKeyParse,
                    )
                })?;
                Ok(Box::new(SoftwareIkeSigningKey {
                    algorithm,
                    kind: SoftwareSigningKeyKind::EcdsaP256(Box::new(key)),
                }))
            }
            IkeSignatureAlgorithm::EcdsaP384Sha2_384 => {
                let key = p384::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der).map_err(|_| {
                    CryptoOperationError::with_source(
                        CryptoOperationErrorCode::InvalidSigningKey,
                        Ikev2SignatureKeyError::EcdsaPrivateKeyParse,
                    )
                })?;
                Ok(Box::new(SoftwareIkeSigningKey {
                    algorithm,
                    kind: SoftwareSigningKeyKind::EcdsaP384(Box::new(key)),
                }))
            }
            _ => Err(unsupported_algorithm()),
        }
    }

    fn verify_signature(
        &self,
        algorithm: IkeSignatureAlgorithm,
        public_key_spki_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoOperationError> {
        let public_key =
            Ikev2SignaturePublicKey::from_spki_der(public_key_spki_der).map_err(|error| {
                CryptoOperationError::with_source(
                    CryptoOperationErrorCode::InvalidVerificationKey,
                    error,
                )
            })?;
        match algorithm {
            IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256 => match &public_key {
                Ikev2SignaturePublicKey::Rsa(public) => {
                    rsa_pkcs1v15_sha256_verify(public, message, signature).map_err(|error| {
                        CryptoOperationError::with_source(
                            CryptoOperationErrorCode::SignatureVerificationFailed,
                            error,
                        )
                    })
                }
                _ => Err(CryptoOperationError::new(
                    CryptoOperationErrorCode::SignatureKeyMismatch,
                )),
            },
            IkeSignatureAlgorithm::EcdsaP256Sha2_256 => match &public_key {
                Ikev2SignaturePublicKey::EcdsaP256(public) => {
                    let signature = p256::ecdsa::Signature::from_der(signature).map_err(|_| {
                        CryptoOperationError::new(
                            CryptoOperationErrorCode::SignatureEncodingInvalid,
                        )
                    })?;
                    let digest = Sha256::digest(message);
                    public.verify_prehash(&digest, &signature).map_err(|_| {
                        CryptoOperationError::new(
                            CryptoOperationErrorCode::SignatureVerificationFailed,
                        )
                    })
                }
                _ => Err(CryptoOperationError::new(
                    CryptoOperationErrorCode::SignatureKeyMismatch,
                )),
            },
            IkeSignatureAlgorithm::EcdsaP384Sha2_384 => match &public_key {
                Ikev2SignaturePublicKey::EcdsaP384(public) => {
                    let signature = p384::ecdsa::Signature::from_der(signature).map_err(|_| {
                        CryptoOperationError::new(
                            CryptoOperationErrorCode::SignatureEncodingInvalid,
                        )
                    })?;
                    let digest = Sha384::digest(message);
                    public.verify_prehash(&digest, &signature).map_err(|_| {
                        CryptoOperationError::new(
                            CryptoOperationErrorCode::SignatureVerificationFailed,
                        )
                    })
                }
                _ => Err(CryptoOperationError::new(
                    CryptoOperationErrorCode::SignatureKeyMismatch,
                )),
            },
            _ => Err(unsupported_algorithm()),
        }
    }
}

enum SoftwareSigningKeyKind {
    #[cfg(feature = "rsa-signing")]
    Rsa(Box<RsaPrivateKey>),
    EcdsaP256(Box<p256::ecdsa::SigningKey>),
    EcdsaP384(Box<p384::ecdsa::SigningKey>),
}

/// Opaque wrapper keeping the RustCrypto private-key types out of the
/// provider boundary. The wrapped keys zeroize their material on drop.
struct SoftwareIkeSigningKey {
    algorithm: IkeSignatureAlgorithm,
    kind: SoftwareSigningKeyKind,
}

impl IkeSigningKey for SoftwareIkeSigningKey {
    fn algorithm(&self) -> IkeSignatureAlgorithm {
        self.algorithm
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoOperationError> {
        match &self.kind {
            #[cfg(feature = "rsa-signing")]
            SoftwareSigningKeyKind::Rsa(private) => rsa_pkcs1v15_sha256_sign(private, message)
                .map_err(|error| {
                    CryptoOperationError::with_source(
                        CryptoOperationErrorCode::SignatureComputationFailed,
                        error,
                    )
                }),
            SoftwareSigningKeyKind::EcdsaP256(private) => {
                let digest = Sha256::digest(message);
                let signature: p256::ecdsa::Signature =
                    private.sign_prehash(&digest).map_err(|_| {
                        CryptoOperationError::new(
                            CryptoOperationErrorCode::SignatureComputationFailed,
                        )
                    })?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
            SoftwareSigningKeyKind::EcdsaP384(private) => {
                let digest = Sha384::digest(message);
                let signature: p384::ecdsa::Signature =
                    private.sign_prehash(&digest).map_err(|_| {
                        CryptoOperationError::new(
                            CryptoOperationErrorCode::SignatureComputationFailed,
                        )
                    })?;
                Ok(signature.to_der().as_bytes().to_vec())
            }
        }
    }
}

impl fmt::Debug for SoftwareIkeSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareIkeSigningKey")
            .field("algorithm", &self.algorithm.as_str())
            .finish()
    }
}
