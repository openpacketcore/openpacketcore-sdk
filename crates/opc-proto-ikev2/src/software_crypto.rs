//! Default software implementation of the `opc-crypto-provider` IKE
//! operation traits.
//!
//! [`Ikev2SoftwareCryptoOperations`] delegates every operation to the
//! algorithm code that already backs this crate's IKEv2 helpers — the same
//! HMAC-SHA1/SHA2 composition, AES-GCM/AES-CBC primitives, DH/ECDH agreement, and
//! RSA/ECDSA signature calls — so its outputs are byte-identical to the
//! existing code paths. The public IKEv2 crypto paths execute through the
//! process-wide admitted module; this software implementation is one explicit
//! module choice rather than an implicit fallback. Secret-bearing outputs use
//! [`zeroize::Zeroizing`], and the opaque [`IkeDhKeyPair`]/[`IkeSigningKey`]
//! handles keep backend-native private-key types out of the provider boundary.
//!
//! @spec IETF RFC7296 2.13-2.14, 3.14; IETF RFC4868 2.6-2.7; IETF RFC5282 3;
//! IETF RFC7427
//! @req REQ-IETF-RFC7296-SA-INIT-CRYPTO-MATERIAL-001

use std::{fmt, sync::Arc};

use opc_crypto_provider::ops::{
    CryptoOperationError, CryptoOperationErrorCode, IkeAeadAlgorithm, IkeCbcAlgorithm, IkeDhGroup,
    IkeDhKeyPair, IkeDiffieHellmanOperations, IkeEncryptionOperations, IkeEntropyOperations,
    IkeHashAlgorithm, IkeHashOperations, IkeIntegrityAlgorithm, IkeIntegrityOperations,
    IkePrfAlgorithm, IkePrfOperations, IkeSignatureAlgorithm, IkeSignatureOperations,
    IkeSigningKey,
};
use opc_crypto_provider::{
    CapabilityReport, CapabilitySet, CryptoCapability, CryptoModule, ModuleReadiness,
    ProviderIdentity, ProviderLabelError, SelfTestError, SelfTestEvidence, SelfTestOutcome,
    ValidationState,
};
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rand::{rngs::SysRng, TryRng};
#[cfg(feature = "rsa-signing")]
use rsa::{traits::PublicKeyParts, RsaPrivateKey};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest, Sha256, Sha384};
use zeroize::Zeroizing;

#[cfg(feature = "rsa-signing")]
use crate::ike_auth_signature::rsa_pkcs1v15_sha256_sign;
use crate::{
    crypto_module::{
        install_ikev2_crypto_module_with_report, Ikev2CryptoModuleInstallError,
        Ikev2CryptoRequirements,
    },
    ike_auth_signature::rsa_pkcs1v15_sha256_verify,
    protected_payload_crypto::{
        software_compute_integrity_checksum, software_decrypt_aes_cbc_in_place,
        software_decrypt_aes_gcm, software_encrypt_aes_cbc, software_encrypt_aes_gcm,
        software_verify_integrity_checksum, Ikev2ProtectedPayloadCryptoError,
        SelectedProtectedPayloadKeys, IKEV2_AES_CBC_IV_LEN, IKEV2_AES_GCM_EXPLICIT_IV_LEN,
    },
    sa_init_crypto::{
        software_prf, software_prf_plus, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
        Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm, Ikev2SaInitCryptoError, SoftwareEphemeralDhKey,
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

const SOFTWARE_CAPABILITIES: CapabilitySet = CapabilitySet::empty()
    .with(CryptoCapability::IkePrf)
    .with(CryptoCapability::IkeHash)
    .with(CryptoCapability::IkeIntegrity)
    .with(CryptoCapability::IkeEncryption)
    .with(CryptoCapability::IkeSignature)
    .with(CryptoCapability::IkeDiffieHellman)
    .with(CryptoCapability::ApprovedEntropy)
    .with(CryptoCapability::Zeroization);

/// SDK RustCrypto-backed IKEv2 module with explicit evidence and operations.
///
/// Constructing this value does not install it. Use
/// [`install_ikev2_software_crypto_module`] from the runtime security-init
/// phase to make the selection explicit and process-wide.
#[derive(Debug, Clone)]
pub struct Ikev2SoftwareCryptoModule {
    identity: ProviderIdentity,
    operations: Ikev2SoftwareCryptoOperations,
}

impl Ikev2SoftwareCryptoModule {
    /// Build the SDK software module with its bounded, non-secret identity.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderLabelError`] if the SDK's built-in identity labels do
    /// not satisfy the provider crate's bounds.
    pub fn new() -> Result<Self, ProviderLabelError> {
        Ok(Self {
            identity: ProviderIdentity::from_parts(
                "opc-ikev2-rustcrypto",
                env!("CARGO_PKG_VERSION"),
            )?,
            operations: Ikev2SoftwareCryptoOperations::new(),
        })
    }

    /// Run the synchronous software power-on checks and assemble evidence.
    #[must_use = "capability evidence must be admitted or published"]
    pub fn capability_report(&self) -> CapabilityReport {
        let outcome = software_self_test(&self.operations);
        CapabilityReport::new(
            self.identity.clone(),
            ValidationState::NotValidated,
            SOFTWARE_CAPABILITIES,
            SelfTestEvidence::Completed(outcome),
            ModuleReadiness::serviceable(SOFTWARE_CAPABILITIES),
        )
    }
}

/// Explicitly preflight and install the SDK software IKEv2 module.
///
/// This synchronous convenience is suitable for a runtime `init_security`
/// callback and for integration-test process setup. It performs the same
/// power-on checks, policy admission, and atomic once-only installation as
/// [`crate::install_ikev2_crypto_module`]. It is never invoked implicitly in
/// a production build.
///
/// # Errors
///
/// Returns [`Ikev2CryptoModuleInstallError`] when identity construction,
/// self-test evidence, policy admission, algorithm preflight, or once-only
/// installation fails.
pub fn install_ikev2_software_crypto_module(
    policy: opc_crypto_provider::ProviderPolicy,
    requirements: Ikev2CryptoRequirements,
) -> Result<CapabilityReport, Ikev2CryptoModuleInstallError> {
    let module = Ikev2SoftwareCryptoModule::new()
        .map_err(|_| Ikev2CryptoModuleInstallError::SoftwareIdentityInvalid)?;
    let report = module.capability_report();
    install_ikev2_crypto_module_with_report(Arc::new(module), policy, requirements, report)
}

#[async_trait::async_trait]
impl CryptoModule for Ikev2SoftwareCryptoModule {
    fn identity(&self) -> ProviderIdentity {
        self.identity.clone()
    }

    fn validation_state(&self) -> ValidationState {
        ValidationState::NotValidated
    }

    fn advertised_capabilities(&self) -> CapabilitySet {
        SOFTWARE_CAPABILITIES
    }

    async fn self_test(&self) -> Result<SelfTestOutcome, SelfTestError> {
        Ok(software_self_test(&self.operations))
    }

    fn readiness(&self) -> ModuleReadiness {
        ModuleReadiness::serviceable(SOFTWARE_CAPABILITIES)
    }
}

impl IkeHashOperations for Ikev2SoftwareCryptoModule {
    fn supports_hash(&self, algorithm: IkeHashAlgorithm) -> bool {
        self.operations.supports_hash(algorithm)
    }

    fn hash(
        &self,
        algorithm: IkeHashAlgorithm,
        parts: &[&[u8]],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.operations.hash(algorithm, parts)
    }
}

impl IkeEntropyOperations for Ikev2SoftwareCryptoModule {
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoOperationError> {
        self.operations.fill_random(output)
    }
}

impl IkePrfOperations for Ikev2SoftwareCryptoModule {
    fn supports_prf(&self, algorithm: IkePrfAlgorithm) -> bool {
        self.operations.supports_prf(algorithm)
    }

    fn prf(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.operations.prf(algorithm, key, data)
    }

    fn prf_plus(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        seed: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.operations.prf_plus(algorithm, key, seed, output_len)
    }
}

impl IkeIntegrityOperations for Ikev2SoftwareCryptoModule {
    fn supports_integrity(&self, algorithm: IkeIntegrityAlgorithm) -> bool {
        self.operations.supports_integrity(algorithm)
    }

    fn compute_integrity_checksum(
        &self,
        algorithm: IkeIntegrityAlgorithm,
        key: &[u8],
        message_prefix: &[u8],
        message_suffix: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.operations
            .compute_integrity_checksum(algorithm, key, message_prefix, message_suffix)
    }

    fn verify_integrity_checksum(
        &self,
        algorithm: IkeIntegrityAlgorithm,
        key: &[u8],
        authenticated_message: &[u8],
        received_icv: &[u8],
    ) -> Result<(), CryptoOperationError> {
        self.operations.verify_integrity_checksum(
            algorithm,
            key,
            authenticated_message,
            received_icv,
        )
    }
}

impl IkeEncryptionOperations for Ikev2SoftwareCryptoModule {
    fn supports_aead(&self, algorithm: IkeAeadAlgorithm) -> bool {
        self.operations.supports_aead(algorithm)
    }

    fn supports_cbc(&self, algorithm: IkeCbcAlgorithm) -> bool {
        self.operations.supports_cbc(algorithm)
    }

    fn seal_aead(
        &self,
        algorithm: IkeAeadAlgorithm,
        key: &[u8],
        salt: &[u8],
        explicit_iv: &[u8],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoOperationError> {
        self.operations.seal_aead(
            algorithm,
            key,
            salt,
            explicit_iv,
            associated_data,
            plaintext,
        )
    }

    fn open_aead(
        &self,
        algorithm: IkeAeadAlgorithm,
        key: &[u8],
        salt: &[u8],
        associated_data: &[u8],
        protected_body: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.operations
            .open_aead(algorithm, key, salt, associated_data, protected_body)
    }

    fn encrypt_cbc(
        &self,
        algorithm: IkeCbcAlgorithm,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoOperationError> {
        self.operations.encrypt_cbc(algorithm, key, iv, plaintext)
    }

    fn decrypt_cbc(
        &self,
        algorithm: IkeCbcAlgorithm,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.operations.decrypt_cbc(algorithm, key, iv, ciphertext)
    }
}

impl IkeDiffieHellmanOperations for Ikev2SoftwareCryptoModule {
    fn supports_dh_group(&self, group: IkeDhGroup) -> bool {
        self.operations.supports_dh_group(group)
    }

    fn generate_keypair(
        &self,
        group: IkeDhGroup,
    ) -> Result<Box<dyn IkeDhKeyPair>, CryptoOperationError> {
        self.operations.generate_keypair(group)
    }
}

impl IkeSignatureOperations for Ikev2SoftwareCryptoModule {
    fn supports_signature_verification(&self, algorithm: IkeSignatureAlgorithm) -> bool {
        self.operations.supports_signature_verification(algorithm)
    }

    fn supports_signature_generation(&self, algorithm: IkeSignatureAlgorithm) -> bool {
        self.operations.supports_signature_generation(algorithm)
    }

    fn load_signing_key(
        &self,
        algorithm: IkeSignatureAlgorithm,
        pkcs8_der: &[u8],
    ) -> Result<Box<dyn IkeSigningKey>, CryptoOperationError> {
        self.operations.load_signing_key(algorithm, pkcs8_der)
    }

    fn verify_signature(
        &self,
        algorithm: IkeSignatureAlgorithm,
        public_key_spki_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoOperationError> {
        self.operations
            .verify_signature(algorithm, public_key_spki_der, message, signature)
    }
}

fn software_self_test(operations: &Ikev2SoftwareCryptoOperations) -> SelfTestOutcome {
    let hash_ok = operations
        .hash(IkeHashAlgorithm::Sha1, &[b"abc"])
        .is_ok_and(|digest| {
            digest.as_slice()
                == [
                    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78,
                    0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
                ]
        });
    let sha1_prf_ok = operations
        .prf(IkePrfAlgorithm::HmacSha1, &[0x0b; 20], b"Hi There")
        .is_ok_and(|output| {
            output.as_slice()
                == [
                    0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb,
                    0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
                ]
        });
    let sha2_prf_ok = operations
        .prf(IkePrfAlgorithm::HmacSha2_256, &[0x0b; 20], b"Hi There")
        .is_ok_and(|output| {
            output.as_slice()
                == [
                    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf,
                    0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9,
                    0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
                ]
        });
    let prf_ok = sha1_prf_ok && sha2_prf_ok;
    let integrity_key = [0x0b; 32];
    let sha2_integrity_ok = operations
        .compute_integrity_checksum(
            IkeIntegrityAlgorithm::HmacSha2_256_128,
            &integrity_key,
            b"software ",
            b"self-test",
        )
        .is_ok_and(|checksum| {
            operations
                .verify_integrity_checksum(
                    IkeIntegrityAlgorithm::HmacSha2_256_128,
                    &integrity_key,
                    b"software self-test",
                    &checksum,
                )
                .is_ok()
        });
    let sha1_integrity_key = [0x0c; 20];
    let sha1_integrity_ok = operations
        .compute_integrity_checksum(
            IkeIntegrityAlgorithm::HmacSha1_96,
            &sha1_integrity_key,
            b"Test With ",
            b"Truncation",
        )
        .is_ok_and(|checksum| {
            checksum.as_slice()
                == [
                    0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f, 0xe7, 0xf2, 0x7b, 0xe1,
                ]
                && operations
                    .verify_integrity_checksum(
                        IkeIntegrityAlgorithm::HmacSha1_96,
                        &sha1_integrity_key,
                        b"Test With Truncation",
                        &checksum,
                    )
                    .is_ok()
        });
    let integrity_ok = sha1_integrity_ok && sha2_integrity_ok;
    let aead_key = [0x11; 16];
    let aead_salt = [0x22; 4];
    let aead_iv = [0x33; 8];
    let aead_ok = operations
        .seal_aead(
            IkeAeadAlgorithm::AesGcm16_128,
            &aead_key,
            &aead_salt,
            &aead_iv,
            b"aad",
            b"software self-test",
        )
        .is_ok_and(|body| {
            operations
                .open_aead(
                    IkeAeadAlgorithm::AesGcm16_128,
                    &aead_key,
                    &aead_salt,
                    b"aad",
                    &body,
                )
                .is_ok_and(|plaintext| plaintext.as_slice() == b"software self-test")
        });
    let cbc_key = [0x44; 16];
    let cbc_iv = [0x55; 16];
    let cbc_plaintext = [0x66; 16];
    let cbc_ok = operations
        .encrypt_cbc(
            IkeCbcAlgorithm::AesCbc128,
            &cbc_key,
            &cbc_iv,
            &cbc_plaintext,
        )
        .is_ok_and(|ciphertext| {
            operations
                .decrypt_cbc(IkeCbcAlgorithm::AesCbc128, &cbc_key, &cbc_iv, &ciphertext)
                .is_ok_and(|plaintext| plaintext.as_slice() == cbc_plaintext)
        });
    let dh_ok = match (
        operations.generate_keypair(IkeDhGroup::Ecp256),
        operations.generate_keypair(IkeDhGroup::Ecp256),
    ) {
        (Ok(left), Ok(right)) => match (
            left.agree(right.public_value()),
            right.agree(left.public_value()),
        ) {
            (Ok(left_secret), Ok(right_secret)) => left_secret == right_secret,
            _ => false,
        },
        _ => false,
    };
    let signature_ok = software_signature_self_test(operations);
    let mut entropy_probe = Zeroizing::new([0_u8; 32]);
    let entropy_ok = operations.fill_random(&mut *entropy_probe).is_ok();

    let mut passed = CapabilitySet::empty();
    let mut failed = CapabilitySet::empty();
    record_self_test(&mut passed, &mut failed, CryptoCapability::IkeHash, hash_ok);
    record_self_test(&mut passed, &mut failed, CryptoCapability::IkePrf, prf_ok);
    record_self_test(
        &mut passed,
        &mut failed,
        CryptoCapability::IkeIntegrity,
        integrity_ok,
    );
    record_self_test(
        &mut passed,
        &mut failed,
        CryptoCapability::IkeEncryption,
        aead_ok && cbc_ok,
    );
    record_self_test(
        &mut passed,
        &mut failed,
        CryptoCapability::IkeDiffieHellman,
        dh_ok,
    );
    record_self_test(
        &mut passed,
        &mut failed,
        CryptoCapability::ApprovedEntropy,
        dh_ok && entropy_ok,
    );
    record_self_test(
        &mut passed,
        &mut failed,
        CryptoCapability::IkeSignature,
        signature_ok,
    );
    record_self_test(
        &mut passed,
        &mut failed,
        CryptoCapability::Zeroization,
        hash_ok
            && prf_ok
            && integrity_ok
            && aead_ok
            && cbc_ok
            && dh_ok
            && signature_ok
            && entropy_ok,
    );
    SelfTestOutcome::new(passed, failed)
}

fn software_signature_self_test(operations: &Ikev2SoftwareCryptoOperations) -> bool {
    let signing_key = match p256::ecdsa::SigningKey::from_slice(&[0x77; 32]) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let pkcs8 = match signing_key.to_pkcs8_der() {
        Ok(document) => document,
        Err(_) => return false,
    };
    let spki = match signing_key.verifying_key().to_public_key_der() {
        Ok(document) => document,
        Err(_) => return false,
    };
    let key = match operations
        .load_signing_key(IkeSignatureAlgorithm::EcdsaP256Sha2_256, pkcs8.as_bytes())
    {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature = match key.sign(b"software self-test") {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    operations
        .verify_signature(
            IkeSignatureAlgorithm::EcdsaP256Sha2_256,
            spki.as_bytes(),
            b"software self-test",
            &signature,
        )
        .is_ok()
}

fn record_self_test(
    passed: &mut CapabilitySet,
    failed: &mut CapabilitySet,
    capability: CryptoCapability,
    ok: bool,
) {
    if ok {
        *passed = passed.with(capability);
    } else {
        *failed = failed.with(capability);
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
        IkePrfAlgorithm::HmacSha1 => Ok(Ikev2PrfAlgorithm::HmacSha1),
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
        IkeIntegrityAlgorithm::HmacSha1_96 => Ok(Ikev2IntegrityAlgorithm::HmacSha1_96),
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
        IkeDhGroup::Modp768 => Ok(Ikev2DhGroup::Modp768),
        IkeDhGroup::Modp1024 => Ok(Ikev2DhGroup::Modp1024),
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
        Ikev2SaInitCryptoError::MalformedKeyExchange { .. } => {
            CryptoOperationErrorCode::InvalidInputLength
        }
        Ikev2SaInitCryptoError::KeyGenerationFailed { .. } => {
            CryptoOperationErrorCode::KeyGenerationFailed
        }
        Ikev2SaInitCryptoError::KeyAgreementFailed { .. } => {
            CryptoOperationErrorCode::KeyAgreementFailed
        }
        _ => CryptoOperationErrorCode::OperationFailed,
    };
    CryptoOperationError::new(code)
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
    CryptoOperationError::new(code)
}

impl IkeHashOperations for Ikev2SoftwareCryptoOperations {
    fn supports_hash(&self, algorithm: IkeHashAlgorithm) -> bool {
        matches!(algorithm, IkeHashAlgorithm::Sha1)
    }

    fn hash(
        &self,
        algorithm: IkeHashAlgorithm,
        parts: &[&[u8]],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        match algorithm {
            IkeHashAlgorithm::Sha1 => {
                let mut hasher = Sha1::new();
                for part in parts {
                    hasher.update(part);
                }
                Ok(Zeroizing::new(hasher.finalize().to_vec()))
            }
            _ => Err(unsupported_algorithm()),
        }
    }
}

impl IkeEntropyOperations for Ikev2SoftwareCryptoOperations {
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoOperationError> {
        SysRng.try_fill_bytes(output).map_err(|_| {
            output.fill(0);
            CryptoOperationError::new(CryptoOperationErrorCode::EntropyUnavailable)
        })
    }
}

impl IkePrfOperations for Ikev2SoftwareCryptoOperations {
    fn supports_prf(&self, algorithm: IkePrfAlgorithm) -> bool {
        matches!(
            algorithm,
            IkePrfAlgorithm::HmacSha1
                | IkePrfAlgorithm::HmacSha2_256
                | IkePrfAlgorithm::HmacSha2_384
                | IkePrfAlgorithm::HmacSha2_512
        )
    }

    fn prf(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        let algorithm = map_prf_algorithm(algorithm)?;
        software_prf(algorithm, key, data).map_err(map_sa_init_error)
    }

    fn prf_plus(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        seed: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        let algorithm = map_prf_algorithm(algorithm)?;
        software_prf_plus(algorithm, key, seed, output_len).map_err(map_sa_init_error)
    }
}

impl IkeIntegrityOperations for Ikev2SoftwareCryptoOperations {
    fn supports_integrity(&self, algorithm: IkeIntegrityAlgorithm) -> bool {
        matches!(
            algorithm,
            IkeIntegrityAlgorithm::HmacSha1_96
                | IkeIntegrityAlgorithm::HmacSha2_256_128
                | IkeIntegrityAlgorithm::HmacSha2_384_192
                | IkeIntegrityAlgorithm::HmacSha2_512_256
        )
    }

    fn compute_integrity_checksum(
        &self,
        algorithm: IkeIntegrityAlgorithm,
        key: &[u8],
        message_prefix: &[u8],
        message_suffix: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        let algorithm = map_integrity_algorithm(algorithm)?;
        software_compute_integrity_checksum(algorithm, key, message_prefix, message_suffix)
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
        software_verify_integrity_checksum(algorithm, key, authenticated_message, received_icv)
            .map_err(map_protected_payload_error)
    }
}

impl IkeEncryptionOperations for Ikev2SoftwareCryptoOperations {
    fn supports_aead(&self, algorithm: IkeAeadAlgorithm) -> bool {
        matches!(
            algorithm,
            IkeAeadAlgorithm::AesGcm16_128
                | IkeAeadAlgorithm::AesGcm16_192
                | IkeAeadAlgorithm::AesGcm16_256
        )
    }

    fn supports_cbc(&self, algorithm: IkeCbcAlgorithm) -> bool {
        matches!(
            algorithm,
            IkeCbcAlgorithm::AesCbc128 | IkeCbcAlgorithm::AesCbc192 | IkeCbcAlgorithm::AesCbc256
        )
    }

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
        software_encrypt_aes_gcm(mapped, keys, associated_data, plaintext, explicit_iv)
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
        software_decrypt_aes_gcm(mapped, keys, associated_data, protected_body)
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
        software_encrypt_aes_cbc(mapped, key, iv, &mut buffer)
            .map_err(map_protected_payload_error)?;
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
        software_decrypt_aes_cbc_in_place(mapped, key, iv, &mut buffer)
            .map_err(map_protected_payload_error)?;
        Ok(buffer)
    }
}

impl IkeDiffieHellmanOperations for Ikev2SoftwareCryptoOperations {
    fn supports_dh_group(&self, group: IkeDhGroup) -> bool {
        matches!(
            group,
            IkeDhGroup::Modp768
                | IkeDhGroup::Modp1024
                | IkeDhGroup::Modp2048
                | IkeDhGroup::Ecp256
                | IkeDhGroup::Ecp384
                | IkeDhGroup::Ecp521
        )
    }

    fn generate_keypair(
        &self,
        group: IkeDhGroup,
    ) -> Result<Box<dyn IkeDhKeyPair>, CryptoOperationError> {
        let mapped = map_dh_group(group)?;
        let inner = SoftwareEphemeralDhKey::generate(mapped).map_err(map_sa_init_error)?;
        Ok(Box::new(SoftwareIkeDhKeyPair { group, inner }))
    }
}

/// Opaque wrapper keeping [`SoftwareEphemeralDhKey`]'s backend-native secret
/// enum out of the provider boundary.
struct SoftwareIkeDhKeyPair {
    group: IkeDhGroup,
    inner: SoftwareEphemeralDhKey,
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
    fn supports_signature_verification(&self, algorithm: IkeSignatureAlgorithm) -> bool {
        matches!(
            algorithm,
            IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256
                | IkeSignatureAlgorithm::EcdsaP256Sha2_256
                | IkeSignatureAlgorithm::EcdsaP384Sha2_256
                | IkeSignatureAlgorithm::EcdsaP384Sha2_384
        )
    }

    fn supports_signature_generation(&self, algorithm: IkeSignatureAlgorithm) -> bool {
        (cfg!(feature = "rsa-signing")
            && matches!(algorithm, IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256))
            || matches!(
                algorithm,
                IkeSignatureAlgorithm::EcdsaP256Sha2_256
                    | IkeSignatureAlgorithm::EcdsaP384Sha2_256
                    | IkeSignatureAlgorithm::EcdsaP384Sha2_384
            )
    }

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
                        CryptoOperationError::new(CryptoOperationErrorCode::InvalidSigningKey)
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
                    CryptoOperationError::new(CryptoOperationErrorCode::InvalidSigningKey)
                })?;
                Ok(Box::new(SoftwareIkeSigningKey {
                    algorithm,
                    kind: SoftwareSigningKeyKind::EcdsaP256(Box::new(key)),
                }))
            }
            IkeSignatureAlgorithm::EcdsaP384Sha2_256 | IkeSignatureAlgorithm::EcdsaP384Sha2_384 => {
                let key = p384::ecdsa::SigningKey::from_pkcs8_der(pkcs8_der).map_err(|_| {
                    CryptoOperationError::new(CryptoOperationErrorCode::InvalidSigningKey)
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
            Ikev2SignaturePublicKey::from_spki_der(public_key_spki_der).map_err(|_| {
                CryptoOperationError::new(CryptoOperationErrorCode::InvalidVerificationKey)
            })?;
        match algorithm {
            IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256 => match &public_key {
                Ikev2SignaturePublicKey::Rsa(public) => {
                    rsa_pkcs1v15_sha256_verify(public, message, signature).map_err(|_| {
                        CryptoOperationError::new(
                            CryptoOperationErrorCode::SignatureVerificationFailed,
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
            IkeSignatureAlgorithm::EcdsaP384Sha2_256 => match &public_key {
                Ikev2SignaturePublicKey::EcdsaP384(public) => {
                    let signature = p384::ecdsa::Signature::from_der(signature).map_err(|_| {
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

    fn rsa_modulus_len(&self) -> Option<usize> {
        match &self.kind {
            #[cfg(feature = "rsa-signing")]
            SoftwareSigningKeyKind::Rsa(private) => Some(private.size()),
            SoftwareSigningKeyKind::EcdsaP256(_) | SoftwareSigningKeyKind::EcdsaP384(_) => None,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoOperationError> {
        match &self.kind {
            #[cfg(feature = "rsa-signing")]
            SoftwareSigningKeyKind::Rsa(private) => rsa_pkcs1v15_sha256_sign(private, message)
                .map_err(|_| {
                    CryptoOperationError::new(CryptoOperationErrorCode::SignatureComputationFailed)
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
                let digest = match self.algorithm {
                    IkeSignatureAlgorithm::EcdsaP384Sha2_256 => Sha256::digest(message).to_vec(),
                    _ => Sha384::digest(message).to_vec(),
                };
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
