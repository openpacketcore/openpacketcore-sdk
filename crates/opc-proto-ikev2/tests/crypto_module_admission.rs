//! Process-isolated proof for IKEv2 crypto-module admission and routing.

use std::{
    fmt,
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll, Waker},
};

use async_trait::async_trait;
use opc_crypto_provider::{
    CapabilitySet, CryptoCapability, CryptoModule, CryptoOperationError, CryptoOperationErrorCode,
    IkeAeadAlgorithm, IkeCbcAlgorithm, IkeCryptoModule, IkeDhGroup, IkeDhKeyPair,
    IkeDiffieHellmanOperations, IkeEncryptionOperations, IkeEntropyOperations, IkeHashAlgorithm,
    IkeHashOperations, IkeIntegrityAlgorithm, IkeIntegrityOperations, IkePrfAlgorithm,
    IkePrfOperations, IkeSignatureAlgorithm, IkeSignatureOperations, IkeSigningKey,
    ModuleReadiness, ProviderIdentity, ProviderPolicy, SelfTestError, SelfTestOutcome,
    ValidationState,
};
use opc_proto_ikev2::{
    compute_ike_auth_signature, decrypt_ikev2_sa_init_protected_payload,
    derive_ike_sa_init_key_material, ikev2_aes_cbc_protected_body_len,
    ikev2_aes_gcm_protected_body_len, ikev2_certreq_authority_key_hash, ikev2_nat_detection_hash,
    inspect_ikev2_signature_key_pkcs8_der, install_ikev2_crypto_module,
    negotiate_ikev2_signature_hash_algorithms, seal_ikev2_sa_init_aes_cbc_protected_payload,
    seal_ikev2_sa_init_protected_payload, verify_ike_auth_signature,
    verify_local_ike_auth_signature, Header, HeaderFlags, Ikev2AuthenticationPayload,
    Ikev2CertReqSubjectPublicKeyInfo, Ikev2CertReqSubjectPublicKeyInfoError,
    Ikev2CryptoModuleErrorCode, Ikev2CryptoModuleInstallError, Ikev2CryptoRequirements,
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2EphemeralDhKey, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2IkeAuthVerificationError, Ikev2IntegrityAlgorithm,
    Ikev2PrfAlgorithm, Ikev2ProtectedPayloadCryptoError, Ikev2ProtectedPayloadDirection,
    Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile, Ikev2SignatureAuthKey,
    Ikev2SignatureHashAlgorithm, Ikev2SignatureHashLocalRole, Ikev2SignatureHashSigningAuthority,
    Ikev2SignatureHashVerificationAuthority, Ikev2SignaturePublicKey, Ikev2SoftwareCryptoModule,
    Ikev2SoftwareCryptoOperations, PayloadType, ProtectedPayloadContext, ProtectedPayloadKind,
    ProtectedPayloadSealContext, IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
    IKEV2_CERTREQ_SUBJECT_PUBLIC_KEY_INFO_MAX_LEN,
};
use opc_protocol::DecodeContext;
use zeroize::Zeroizing;

#[path = "support/canonical.rs"]
mod canonical_fixtures;
mod support;

struct ObservedAead {
    key_nonce: Vec<u8>,
    aad: Vec<u8>,
    plaintext: Vec<u8>,
}

const P256_PKCS8_DER: &[u8] = include_bytes!("data/p256_pkcs8.der");
const P256_SPKI_DER: &[u8] = include_bytes!("data/p256_spki.der");
const P256_CERT_DER: &[u8] = include_bytes!("data/p256_cert.der");
// Independently computed with OpenSSL 3:
// `openssl dgst -sha1 tests/data/p256_spki.der`.
const P256_SPKI_SHA1: [u8; 20] = [
    0xa2, 0x37, 0x81, 0xbb, 0x75, 0xce, 0x80, 0xc8, 0xfb, 0xf0, 0x6f, 0xcc, 0xcf, 0x4a, 0x6f, 0xc3,
    0xdb, 0x45, 0x95, 0x72,
];
const HOSTILE_PROVIDER_DIAGNOSTIC: &str = "hostile-provider-diagnostic-marker";
const HOSTILE_PROVIDER_OUTPUT: &[u8] = b"hostile-provider-output-marker";
#[cfg(feature = "rsa-signing")]
const RSA2048_PKCS8_DER: &[u8] = include_bytes!("data/rsa2048_pkcs8.der");

fn signature_hash_authorities() -> (
    Vec<u8>,
    Vec<u8>,
    Ikev2SignatureHashSigningAuthority,
    Ikev2SignatureHashVerificationAuthority,
) {
    let hashes = [Ikev2SignatureHashAlgorithm::Sha2_256];
    let (request, response) = support::signature_hash_exchange(Some(&hashes), Some(&hashes));
    let responder = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Responder,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("responder test signature-hash negotiation")
    .into_authorities()
    .into_parts();
    let initiator = negotiate_ikev2_signature_hash_algorithms(
        Ikev2SignatureHashLocalRole::Initiator,
        &request,
        &response,
        DecodeContext::default(),
    )
    .expect("initiator test signature-hash negotiation")
    .into_authorities()
    .into_parts();
    (request, response, responder.0, initiator.1)
}

fn spki_with_extra_outer_element() -> Vec<u8> {
    let mut der = P256_SPKI_DER.to_vec();
    assert_eq!(der.get(1), Some(&0x59), "fixture outer length changed");
    der[1] = 0x5b;
    der.extend_from_slice(&[0x05, 0x00]);
    der
}

fn spki_with_extra_algorithm_identifier_element() -> Vec<u8> {
    let mut der = P256_SPKI_DER.to_vec();
    assert_eq!(der.get(1), Some(&0x59), "fixture outer length changed");
    assert_eq!(
        der.get(3),
        Some(&0x13),
        "fixture AlgorithmIdentifier length changed"
    );
    der[1] = 0x5b;
    der[3] = 0x15;
    der.splice(23..23, [0x05, 0x00]);
    der
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum MalformedOutput {
    None,
    Hash,
    Prf,
    PrfPlus,
    Integrity,
    AeadSeal,
    AeadSealWrongExplicitIv,
    AeadOpen,
    CbcEncrypt,
    CbcDecrypt,
    DhGroup,
    DhPublic,
    DhSemanticPublic,
    DhAgree,
    SigningAlgorithm,
    SigningEmpty,
    SigningMalformedDer,
    SigningOutOfRange,
    SigningRsaWrongWidth,
}

#[derive(Default)]
struct OperationCounts {
    hash: AtomicUsize,
    entropy: AtomicUsize,
    prf: AtomicUsize,
    integrity: AtomicUsize,
    encryption: AtomicUsize,
    dh_generate: AtomicUsize,
    dh_agree: AtomicUsize,
    signature_load: AtomicUsize,
    signature_sign: AtomicUsize,
    signature_verify: AtomicUsize,
}

impl OperationCounts {
    fn snapshot(&self) -> [usize; 10] {
        [
            self.hash.load(Ordering::SeqCst),
            self.entropy.load(Ordering::SeqCst),
            self.prf.load(Ordering::SeqCst),
            self.integrity.load(Ordering::SeqCst),
            self.encryption.load(Ordering::SeqCst),
            self.dh_generate.load(Ordering::SeqCst),
            self.dh_agree.load(Ordering::SeqCst),
            self.signature_load.load(Ordering::SeqCst),
            self.signature_sign.load(Ordering::SeqCst),
            self.signature_verify.load(Ordering::SeqCst),
        ]
    }
}

struct CountingModule {
    inner: Ikev2SoftwareCryptoModule,
    operations: Ikev2SoftwareCryptoOperations,
    identity: ProviderIdentity,
    drifted_identity: ProviderIdentity,
    advertised: Mutex<CapabilitySet>,
    serviceable: Mutex<CapabilitySet>,
    identity_reads: AtomicUsize,
    drift_identity_after_first_read: AtomicBool,
    readiness_reads: AtomicUsize,
    withdraw_extra_after_first_readiness: AtomicBool,
    reject_prf_support: AtomicBool,
    reject_hash_support: AtomicBool,
    fail_hash_operation: AtomicBool,
    drift_validation: AtomicBool,
    withdraw_signature_after_next_prf: AtomicBool,
    malformed_output: Arc<AtomicU8>,
    counts: Arc<OperationCounts>,
    provider_diagnostic: &'static str,
    protocol_msk_uses: AtomicUsize,
    panic_protocol_msk: AtomicBool,
    sync_entropy_mode: AtomicU8,
    sync_entropy_byte: AtomicU8,
    canonical_fault: AtomicU8,
    canonical_failures: AtomicUsize,
    canonical_seals: AtomicUsize,
    monitor_aead: AtomicBool,
    observed_aead: Mutex<Vec<ObservedAead>>,
}

impl CountingModule {
    fn new() -> Self {
        let inner = Ikev2SoftwareCryptoModule::new().expect("bounded software identity");
        let capabilities = inner
            .advertised_capabilities()
            .with(CryptoCapability::SealedKeyStorage);
        Self {
            inner,
            operations: Ikev2SoftwareCryptoOperations::new(),
            identity: ProviderIdentity::from_parts("counting-ike-module", "1")
                .expect("bounded primary identity"),
            drifted_identity: ProviderIdentity::from_parts("counting-ike-module", "2")
                .expect("bounded drift identity"),
            advertised: Mutex::new(capabilities),
            serviceable: Mutex::new(capabilities),
            identity_reads: AtomicUsize::new(0),
            drift_identity_after_first_read: AtomicBool::new(false),
            readiness_reads: AtomicUsize::new(0),
            withdraw_extra_after_first_readiness: AtomicBool::new(false),
            reject_prf_support: AtomicBool::new(false),
            reject_hash_support: AtomicBool::new(false),
            fail_hash_operation: AtomicBool::new(false),
            drift_validation: AtomicBool::new(false),
            withdraw_signature_after_next_prf: AtomicBool::new(false),
            malformed_output: Arc::new(AtomicU8::new(MalformedOutput::None as u8)),
            counts: Arc::new(OperationCounts::default()),
            provider_diagnostic: HOSTILE_PROVIDER_DIAGNOSTIC,
            protocol_msk_uses: AtomicUsize::new(0),
            panic_protocol_msk: AtomicBool::new(false),
            sync_entropy_mode: AtomicU8::new(0),
            sync_entropy_byte: AtomicU8::new(0xa5),
            canonical_fault: AtomicU8::new(0),
            canonical_failures: AtomicUsize::new(0),
            canonical_seals: AtomicUsize::new(0),
            monitor_aead: AtomicBool::new(false),
            observed_aead: Mutex::new(Vec::new()),
        }
    }

    fn capabilities(&self) -> CapabilitySet {
        self.inner
            .advertised_capabilities()
            .with(CryptoCapability::SealedKeyStorage)
    }

    fn set_advertised(&self, capabilities: CapabilitySet) {
        *self.advertised.lock().expect("advertised lock") = capabilities;
    }

    fn set_serviceable(&self, capabilities: CapabilitySet) {
        *self.serviceable.lock().expect("serviceable lock") = capabilities;
    }

    fn withdraw_signature_after_next_prf(&self) {
        self.withdraw_signature_after_next_prf
            .store(true, Ordering::SeqCst);
    }

    fn maybe_withdraw_signature(&self) {
        if self
            .withdraw_signature_after_next_prf
            .swap(false, Ordering::SeqCst)
        {
            let without_signature = self
                .serviceable
                .lock()
                .expect("serviceable lock")
                .without(CryptoCapability::IkeSignature);
            self.set_serviceable(without_signature);
        }
    }

    fn set_malformed_output(&self, mode: MalformedOutput) {
        self.malformed_output.store(mode as u8, Ordering::SeqCst);
    }

    fn malformed_output(&self, mode: MalformedOutput) -> bool {
        self.malformed_output.load(Ordering::SeqCst) == mode as u8
    }

    fn observe_aead(&self, key: &[u8], salt: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) {
        if !self.monitor_aead.load(Ordering::SeqCst) {
            return;
        }
        let key_nonce = [&[u8::try_from(key.len()).unwrap()][..], key, salt, iv].concat();
        let mut observed = self.observed_aead.lock().unwrap();
        if let Some(previous) = observed.iter().find(|value| value.key_nonce == key_nonce) {
            assert_eq!(
                previous.aad, aad,
                "different AAD under one actual key/nonce"
            );
            assert_eq!(
                previous.plaintext, plaintext,
                "different plaintext under one actual key/nonce"
            );
        }
        observed.push(ObservedAead {
            key_nonce,
            aad: aad.to_vec(),
            plaintext: plaintext.to_vec(),
        });
    }
}

#[async_trait]
impl CryptoModule for CountingModule {
    fn identity(&self) -> ProviderIdentity {
        let read = self.identity_reads.fetch_add(1, Ordering::SeqCst);
        if self.drift_identity_after_first_read.load(Ordering::SeqCst) && read > 0 {
            self.drifted_identity.clone()
        } else {
            self.identity.clone()
        }
    }

    fn validation_state(&self) -> ValidationState {
        if self.drift_validation.load(Ordering::SeqCst) {
            ValidationState::DeclaredValidated { reference: None }
        } else {
            ValidationState::NotValidated
        }
    }

    fn advertised_capabilities(&self) -> CapabilitySet {
        *self.advertised.lock().expect("advertised lock")
    }

    async fn self_test(&self) -> Result<SelfTestOutcome, SelfTestError> {
        Ok(SelfTestOutcome::new(
            self.advertised_capabilities(),
            CapabilitySet::empty(),
        ))
    }

    fn readiness(&self) -> ModuleReadiness {
        let mut serviceable = self.serviceable.lock().expect("serviceable lock");
        let snapshot = *serviceable;
        let read = self.readiness_reads.fetch_add(1, Ordering::SeqCst);
        if self
            .withdraw_extra_after_first_readiness
            .load(Ordering::SeqCst)
            && read == 0
        {
            *serviceable = snapshot.without(CryptoCapability::SealedKeyStorage);
        }
        ModuleReadiness::serviceable(snapshot)
    }
}

impl IkeHashOperations for CountingModule {
    fn supports_hash(&self, algorithm: IkeHashAlgorithm) -> bool {
        !self.reject_hash_support.load(Ordering::SeqCst) && self.operations.supports_hash(algorithm)
    }

    fn hash(
        &self,
        algorithm: IkeHashAlgorithm,
        parts: &[&[u8]],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.counts.hash.fetch_add(1, Ordering::SeqCst);
        if self.fail_hash_operation.load(Ordering::SeqCst) {
            let _provider_native_diagnostic = self.provider_diagnostic;
            return Err(CryptoOperationError::new(
                CryptoOperationErrorCode::OperationFailed,
            ));
        }
        let mut output = self.operations.hash(algorithm, parts)?;
        if self.malformed_output(MalformedOutput::Hash) {
            output = Zeroizing::new(HOSTILE_PROVIDER_OUTPUT.to_vec());
        }
        Ok(output)
    }
}

impl IkeEntropyOperations for CountingModule {
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoOperationError> {
        self.counts.entropy.fetch_add(1, Ordering::SeqCst);
        match self.sync_entropy_mode.load(Ordering::SeqCst) {
            1 => {
                output.fill(self.sync_entropy_byte.load(Ordering::SeqCst));
                return Ok(());
            }
            2 => {
                return Err(CryptoOperationError::new(
                    CryptoOperationErrorCode::OperationFailed,
                ))
            }
            _ => {}
        }
        self.operations.fill_random(output)
    }
}

impl IkePrfOperations for CountingModule {
    fn supports_prf(&self, algorithm: IkePrfAlgorithm) -> bool {
        !self.reject_prf_support.load(Ordering::SeqCst) && self.operations.supports_prf(algorithm)
    }

    fn prf(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        data: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.counts.prf.fetch_add(1, Ordering::SeqCst);
        if key == [0x5a; 32] {
            self.protocol_msk_uses.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.panic_protocol_msk.swap(false, Ordering::SeqCst),
                "synthetic protocol-key provider panic"
            );
        }
        let mut result = self.operations.prf(algorithm, key, data);
        if self.malformed_output(MalformedOutput::Prf) {
            if let Ok(output) = &mut result {
                output.pop();
            }
        }
        self.maybe_withdraw_signature();
        result
    }

    fn prf_plus(
        &self,
        algorithm: IkePrfAlgorithm,
        key: &[u8],
        seed: &[u8],
        output_len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.counts.prf.fetch_add(1, Ordering::SeqCst);
        let mut result = self.operations.prf_plus(algorithm, key, seed, output_len);
        if self.malformed_output(MalformedOutput::PrfPlus) {
            if let Ok(output) = &mut result {
                output.pop();
            }
        }
        self.maybe_withdraw_signature();
        result
    }
}

impl IkeIntegrityOperations for CountingModule {
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
        self.counts.integrity.fetch_add(1, Ordering::SeqCst);
        let mut output = self.operations.compute_integrity_checksum(
            algorithm,
            key,
            message_prefix,
            message_suffix,
        )?;
        if self.malformed_output(MalformedOutput::Integrity) {
            output.pop();
        }
        Ok(output)
    }

    fn verify_integrity_checksum(
        &self,
        algorithm: IkeIntegrityAlgorithm,
        key: &[u8],
        authenticated_message: &[u8],
        received_icv: &[u8],
    ) -> Result<(), CryptoOperationError> {
        self.counts.integrity.fetch_add(1, Ordering::SeqCst);
        self.operations.verify_integrity_checksum(
            algorithm,
            key,
            authenticated_message,
            received_icv,
        )
    }
}

impl IkeEncryptionOperations for CountingModule {
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
        self.counts.encryption.fetch_add(1, Ordering::SeqCst);
        self.observe_aead(key, salt, explicit_iv, associated_data, plaintext);
        let canonical = explicit_iv.starts_with(&[0xff; 4]);
        let fault = if canonical {
            self.canonical_seals.fetch_add(1, Ordering::SeqCst);
            let mut left = self.canonical_failures.load(Ordering::SeqCst);
            loop {
                if left == 0 {
                    break 0;
                }
                match self.canonical_failures.compare_exchange_weak(
                    left,
                    left - 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break self.canonical_fault.load(Ordering::SeqCst),
                    Err(current) => left = current,
                }
            }
        } else {
            0
        };
        if fault == 5 {
            return Err(CryptoOperationError::new(
                CryptoOperationErrorCode::OperationFailed,
            ));
        }
        if fault == 6 {
            return Ok([explicit_iv, &[0; 17]].concat());
        }
        let mut output = self.operations.seal_aead(
            algorithm,
            key,
            salt,
            explicit_iv,
            associated_data,
            if fault == 4 { &[1] } else { plaintext },
        )?;
        match fault {
            1 => *output.last_mut().unwrap() ^= 1,
            2 => output[0] ^= 1,
            3 => {
                output.pop();
            }
            _ => {}
        }
        if self.malformed_output(MalformedOutput::AeadSeal) {
            output.pop();
        } else if self.malformed_output(MalformedOutput::AeadSealWrongExplicitIv) {
            if let Some(first) = output.first_mut() {
                *first ^= 1;
            }
        }
        Ok(output)
    }

    fn open_aead(
        &self,
        algorithm: IkeAeadAlgorithm,
        key: &[u8],
        salt: &[u8],
        associated_data: &[u8],
        protected_body: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.counts.encryption.fetch_add(1, Ordering::SeqCst);
        if self.canonical_fault.load(Ordering::SeqCst) == 7
            && protected_body.starts_with(&[0xff; 4])
        {
            panic!("injected interruption before canonical release");
        }
        if self.canonical_fault.load(Ordering::SeqCst) == 6
            && protected_body.starts_with(&[0xff; 4])
        {
            return Ok(Zeroizing::new(vec![0]));
        }
        let mut output =
            self.operations
                .open_aead(algorithm, key, salt, associated_data, protected_body)?;
        if self.malformed_output(MalformedOutput::AeadOpen) {
            output.pop();
        }
        Ok(output)
    }

    fn encrypt_cbc(
        &self,
        algorithm: IkeCbcAlgorithm,
        key: &[u8],
        iv: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoOperationError> {
        self.counts.encryption.fetch_add(1, Ordering::SeqCst);
        let mut output = self.operations.encrypt_cbc(algorithm, key, iv, plaintext)?;
        if self.malformed_output(MalformedOutput::CbcEncrypt) {
            output.pop();
        }
        Ok(output)
    }

    fn decrypt_cbc(
        &self,
        algorithm: IkeCbcAlgorithm,
        key: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.counts.encryption.fetch_add(1, Ordering::SeqCst);
        let mut output = self
            .operations
            .decrypt_cbc(algorithm, key, iv, ciphertext)?;
        if self.malformed_output(MalformedOutput::CbcDecrypt) {
            output.pop();
        }
        Ok(output)
    }
}

impl IkeDiffieHellmanOperations for CountingModule {
    fn supports_dh_group(&self, group: IkeDhGroup) -> bool {
        self.operations.supports_dh_group(group)
    }

    fn generate_keypair(
        &self,
        group: IkeDhGroup,
    ) -> Result<Box<dyn IkeDhKeyPair>, CryptoOperationError> {
        self.counts.dh_generate.fetch_add(1, Ordering::SeqCst);
        self.operations.generate_keypair(group).map(|inner| {
            Box::new(CountingDhKeyPair {
                inner,
                counts: Arc::clone(&self.counts),
                malformed_output: Arc::clone(&self.malformed_output),
                invalid_public_value: vec![0; group.public_value_len()],
            }) as Box<dyn IkeDhKeyPair>
        })
    }
}

struct CountingDhKeyPair {
    inner: Box<dyn IkeDhKeyPair>,
    counts: Arc<OperationCounts>,
    malformed_output: Arc<AtomicU8>,
    invalid_public_value: Vec<u8>,
}

impl fmt::Debug for CountingDhKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CountingDhKeyPair")
            .field("group", &self.inner.group())
            .finish_non_exhaustive()
    }
}

impl IkeDhKeyPair for CountingDhKeyPair {
    fn group(&self) -> IkeDhGroup {
        if self.malformed_output.load(Ordering::SeqCst) == MalformedOutput::DhGroup as u8 {
            IkeDhGroup::Modp2048
        } else {
            self.inner.group()
        }
    }

    fn public_value(&self) -> &[u8] {
        let public_value = self.inner.public_value();
        if self.malformed_output.load(Ordering::SeqCst) == MalformedOutput::DhPublic as u8 {
            &public_value[..public_value.len().saturating_sub(1)]
        } else if self.malformed_output.load(Ordering::SeqCst)
            == MalformedOutput::DhSemanticPublic as u8
        {
            &self.invalid_public_value
        } else {
            public_value
        }
    }

    fn agree(&self, peer_public_value: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.counts.dh_agree.fetch_add(1, Ordering::SeqCst);
        let mut output = self.inner.agree(peer_public_value)?;
        if self.malformed_output.load(Ordering::SeqCst) == MalformedOutput::DhAgree as u8 {
            output.pop();
        }
        Ok(output)
    }
}

impl IkeSignatureOperations for CountingModule {
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
        self.counts.signature_load.fetch_add(1, Ordering::SeqCst);
        self.operations
            .load_signing_key(algorithm, pkcs8_der)
            .map(|inner| {
                Box::new(CountingSigningKey {
                    inner,
                    counts: Arc::clone(&self.counts),
                    malformed_output: Arc::clone(&self.malformed_output),
                }) as Box<dyn IkeSigningKey>
            })
    }

    fn verify_signature(
        &self,
        algorithm: IkeSignatureAlgorithm,
        public_key_spki_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoOperationError> {
        self.counts.signature_verify.fetch_add(1, Ordering::SeqCst);
        self.operations
            .verify_signature(algorithm, public_key_spki_der, message, signature)
    }
}

struct CountingSigningKey {
    inner: Box<dyn IkeSigningKey>,
    counts: Arc<OperationCounts>,
    malformed_output: Arc<AtomicU8>,
}

impl fmt::Debug for CountingSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CountingSigningKey")
            .field("algorithm", &self.inner.algorithm())
            .finish_non_exhaustive()
    }
}

impl IkeSigningKey for CountingSigningKey {
    fn algorithm(&self) -> IkeSignatureAlgorithm {
        if self.malformed_output.load(Ordering::SeqCst) == MalformedOutput::SigningAlgorithm as u8 {
            IkeSignatureAlgorithm::EcdsaP384Sha2_384
        } else {
            self.inner.algorithm()
        }
    }

    fn rsa_modulus_len(&self) -> Option<usize> {
        self.inner.rsa_modulus_len()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoOperationError> {
        self.counts.signature_sign.fetch_add(1, Ordering::SeqCst);
        let mut signature = self.inner.sign(message)?;
        let malformed_output = self.malformed_output.load(Ordering::SeqCst);
        if malformed_output == MalformedOutput::SigningEmpty as u8 {
            signature.clear();
        } else if malformed_output == MalformedOutput::SigningMalformedDer as u8 {
            signature = vec![0x30, 0x01, 0x00];
        } else if malformed_output == MalformedOutput::SigningOutOfRange as u8 {
            signature = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
        } else if malformed_output == MalformedOutput::SigningRsaWrongWidth as u8 {
            signature.pop();
        }
        Ok(signature)
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = Box::pin(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesCbc128,
        Ikev2IntegrityAlgorithm::HmacSha2_256_128,
    )
    .expect("executable test profile")
}

fn aead_profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("executable AEAD test profile")
}

fn requirements(profile: Ikev2SaInitCryptoProfile) -> Ikev2CryptoRequirements {
    let mut requirements = Ikev2CryptoRequirements::new();
    requirements
        .require_ike_sa_profile(profile)
        .expect("profile requirements");
    requirements
        .require_ike_sa_profile(aead_profile())
        .expect("AEAD profile requirements");
    requirements.require_signature(IkeSignatureAlgorithm::EcdsaP256Sha2_256);
    #[cfg(feature = "rsa-signing")]
    requirements.require_signature_generation(IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256);
    requirements.require_nat_detection();
    requirements.require_certreq_authority_hash();
    requirements
}

fn policy(requirements: &Ikev2CryptoRequirements) -> ProviderPolicy {
    ProviderPolicy::new()
        .require_all(requirements.required_capabilities())
        .require(CryptoCapability::SealedKeyStorage)
}

fn protocol_key_uses_only_admitted_prf(
    module: &CountingModule,
    profile: Ikev2SaInitCryptoProfile,
    material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
) {
    use opc_proto_ikev2::protocol_key::{
        Ikev2ProtocolKeyAssociation, Ikev2ProtocolKeyError, Ikev2ProtocolKeyHandle,
        Ikev2ProtocolKeyOperation, Ikev2ProtocolKeyPurpose,
    };
    use std::num::NonZeroU64;
    let id = |v| NonZeroU64::new(v).expect("nonzero synthetic identifier");
    let signed = |peer| Ikev2IkeAuthSignedOctets {
        peer,
        ike_sa_init_message: &[0x11; 28],
        peer_nonce: &[0x22; 32],
        identity_payload_body: &[1, 0, 0, 0, 192, 0, 2, 1],
    };
    let consume = |key: &Ikev2ProtocolKeyHandle, op: &Ikev2ProtocolKeyOperation| {
        key.consume_ike_auth(
            op,
            material,
            signed(Ikev2IkeAuthPeer::Initiator),
            signed(Ikev2IkeAuthPeer::Responder),
            136,
        )
    };
    let fresh = || {
        let owner = Ikev2ProtocolKeyAssociation::new(id(1));
        let operation = owner.begin_ike_auth(id(1), id(1), profile).unwrap();
        let before = module.counts.snapshot();
        let key = operation
            .import(
                Ikev2ProtocolKeyPurpose::N3iwfMsk,
                Zeroizing::new(vec![0x5a; 32]),
            )
            .unwrap();
        assert_eq!(
            module.counts.snapshot(),
            before,
            "import is not crypto execution"
        );
        (owner, operation, key)
    };
    let (_owner, operation, key) = fresh();
    let (_other, foreign, _other_key) = fresh();
    let before = module.counts.snapshot();
    let msk_before = module.protocol_msk_uses.load(Ordering::SeqCst);
    assert_eq!(
        consume(&key, &foreign).unwrap_err(),
        Ikev2ProtocolKeyError::OperationMismatch
    );
    assert_eq!(module.counts.snapshot(), before);
    let start = std::sync::Barrier::new(8);
    let results = std::thread::scope(|scope| {
        let workers = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    consume(&key, &operation)
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Ikev2ProtocolKeyError::Retired)))
            .count(),
        7
    );
    assert_eq!(module.counts.prf.load(Ordering::SeqCst), before[2] + 6);
    assert_eq!(
        module.protocol_msk_uses.load(Ordering::SeqCst),
        msk_before + 2
    );

    for cause in 0..3 {
        let (owner, operation, key) = fresh();
        match cause {
            0 => operation.cancel(),
            1 => owner.release(),
            2 => owner.replace_generation(id(1), id(2)).unwrap(),
            _ => unreachable!(),
        }
        let before = module.counts.snapshot();
        assert!(consume(&key, &operation).is_err());
        assert_eq!(
            module.counts.snapshot(),
            before,
            "retired authority dispatched crypto"
        );
    }
    let all = module.capabilities();
    let (_owner, op, key) = fresh();
    let mut invalid_responder = signed(Ikev2IkeAuthPeer::Responder);
    invalid_responder.identity_payload_body = &[0, 0, 0, 0, 1];
    let before = module.counts.snapshot();
    assert_eq!(
        key.consume_ike_auth(
            &op,
            material,
            signed(Ikev2IkeAuthPeer::Initiator),
            invalid_responder,
            136
        )
        .unwrap_err(),
        Ikev2ProtocolKeyError::InvalidAuthInputs
    );
    assert_eq!(
        module.counts.snapshot(),
        before,
        "invalid second direction used the first direction's key"
    );
    for failure in 0..7 {
        let (_owner, operation, key) = fresh();
        let before = module.counts.prf.load(Ordering::SeqCst);
        let msk_before = module.protocol_msk_uses.load(Ordering::SeqCst);
        match failure {
            0 => module.set_serviceable(all.without(CryptoCapability::IkePrf)),
            1 => module.set_serviceable(all.without(CryptoCapability::Zeroization)),
            2 => module.set_advertised(all.without(CryptoCapability::IkePrf)),
            3 => module.drift_validation.store(true, Ordering::SeqCst),
            4 => module.reject_prf_support.store(true, Ordering::SeqCst),
            5 => module.set_malformed_output(MalformedOutput::Prf),
            6 => module.withdraw_signature_after_next_prf(),
            _ => unreachable!(),
        }
        assert_eq!(
            consume(&key, &operation).unwrap_err(),
            Ikev2ProtocolKeyError::CryptoUnavailable
        );
        assert_eq!(
            module.counts.prf.load(Ordering::SeqCst),
            before + usize::from(failure >= 5)
        );
        assert_eq!(module.protocol_msk_uses.load(Ordering::SeqCst), msk_before);
        module.set_serviceable(all);
        module.set_advertised(all);
        module.drift_validation.store(false, Ordering::SeqCst);
        module.reject_prf_support.store(false, Ordering::SeqCst);
        module.set_malformed_output(MalformedOutput::None);
        let before = module.counts.snapshot();
        assert_eq!(
            consume(&key, &operation).unwrap_err(),
            Ikev2ProtocolKeyError::Retired
        );
        assert_eq!(
            module.counts.snapshot(),
            before,
            "failed consume retried crypto"
        );
    }
    for failure in 0..3 {
        let owner = Ikev2ProtocolKeyAssociation::new(id(1));
        let operation = owner.begin_ike_auth(id(1), id(1), profile).unwrap();
        let before = module.counts.snapshot();
        let purpose = if failure == 0 {
            Ikev2ProtocolKeyPurpose::Unsupported
        } else {
            Ikev2ProtocolKeyPurpose::N3iwfMsk
        };
        if failure == 2 {
            module.set_serviceable(all.without(CryptoCapability::IkePrf));
        }
        let error = operation
            .import(
                purpose,
                Zeroizing::new(vec![0x5a; if failure == 1 { 31 } else { 32 }]),
            )
            .unwrap_err();
        assert_eq!(
            error,
            [
                Ikev2ProtocolKeyError::UnsupportedPurpose,
                Ikev2ProtocolKeyError::InvalidKeyLength,
                Ikev2ProtocolKeyError::CryptoUnavailable
            ][failure]
        );
        assert_eq!(module.counts.snapshot(), before);
        module.set_serviceable(all);
    }
    let (_owner, operation, key) = fresh();
    module.panic_protocol_msk.store(true, Ordering::SeqCst);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| consume(&key, &operation)))
            .is_err()
    );
    let before = module.counts.snapshot();
    assert_eq!(
        consume(&key, &operation).unwrap_err(),
        Ikev2ProtocolKeyError::Unavailable
    );
    assert_eq!(module.counts.snapshot(), before);
}

#[test]
fn child_sa_pfs_requirements_include_dh_and_entropy_capabilities() {
    let child_profile = opc_proto_ikev2::Ikev2ChildSaCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    );
    let mut requirements = Ikev2CryptoRequirements::new();
    requirements
        .require_child_sa_profile(child_profile)
        .require_child_sa_pfs_group(Ikev2DhGroup::Ecp384);

    let capabilities = requirements.required_capabilities();
    assert!(capabilities.contains(CryptoCapability::IkePrf));
    assert!(capabilities.contains(CryptoCapability::IkeDiffieHellman));
    assert!(capabilities.contains(CryptoCapability::ApprovedEntropy));
    assert!(capabilities.contains(CryptoCapability::Zeroization));
}

fn assert_not_installed() {
    let error =
        ikev2_nat_detection_hash(1, 2, "192.0.2.10:500".parse().expect("synthetic endpoint"))
            .expect_err("failed admission must leave the slot unset");
    assert_eq!(error.code(), Ikev2CryptoModuleErrorCode::NotInstalled);

    let spki =
        Ikev2CertReqSubjectPublicKeyInfo::from_der(P256_SPKI_DER).expect("synthetic SPKI is valid");
    let error = ikev2_certreq_authority_key_hash(spki)
        .expect_err("failed admission must leave CERTREQ hashing unavailable");
    assert_eq!(error.code(), Ikev2CryptoModuleErrorCode::NotInstalled);
}

#[test]
fn certreq_spki_input_is_exact_bounded_and_redaction_safe() {
    let valid =
        Ikev2CertReqSubjectPublicKeyInfo::from_der(P256_SPKI_DER).expect("synthetic SPKI is valid");
    assert_eq!(valid.len(), P256_SPKI_DER.len());
    assert!(!valid.is_empty());
    let debug = format!("{valid:?}");
    assert_eq!(
        debug,
        format!(
            "Ikev2CertReqSubjectPublicKeyInfo {{ der_len: {} }}",
            P256_SPKI_DER.len()
        )
    );

    let empty =
        Ikev2CertReqSubjectPublicKeyInfo::from_der(&[]).expect_err("empty SPKI must fail closed");
    assert_eq!(empty, Ikev2CertReqSubjectPublicKeyInfoError::Empty);

    let hostile = b"hostile-certreq-input-marker";
    let malformed = Ikev2CertReqSubjectPublicKeyInfo::from_der(hostile)
        .expect_err("non-DER input must fail closed");
    assert_eq!(
        malformed,
        Ikev2CertReqSubjectPublicKeyInfoError::MalformedDer
    );
    assert_eq!(malformed.as_str(), "ike_certreq_spki_malformed_der");
    assert!(std::error::Error::source(&malformed).is_none());
    assert!(!format!("{malformed}").contains("hostile-certreq-input-marker"));
    assert!(!format!("{malformed:?}").contains("hostile-certreq-input-marker"));

    assert!(Ikev2CertReqSubjectPublicKeyInfo::from_der(P256_CERT_DER).is_err());
    assert!(Ikev2CertReqSubjectPublicKeyInfo::from_der(&P256_SPKI_DER[26..]).is_err());

    for malformed_container in [
        spki_with_extra_outer_element(),
        spki_with_extra_algorithm_identifier_element(),
    ] {
        let error = Ikev2CertReqSubjectPublicKeyInfo::from_der(&malformed_container)
            .expect_err("unconsumed DER inside an SPKI container must fail closed");
        assert_eq!(error, Ikev2CertReqSubjectPublicKeyInfoError::MalformedDer);
    }

    let mut trailing = P256_SPKI_DER.to_vec();
    trailing.extend_from_slice(b"hostile-certreq-trailing-marker");
    let trailing_error = Ikev2CertReqSubjectPublicKeyInfo::from_der(&trailing)
        .expect_err("trailing input must fail closed");
    assert_eq!(
        trailing_error,
        Ikev2CertReqSubjectPublicKeyInfoError::TrailingData
    );
    assert!(!format!("{trailing_error:?}").contains("hostile-certreq-trailing-marker"));

    let overlong = vec![0_u8; IKEV2_CERTREQ_SUBJECT_PUBLIC_KEY_INFO_MAX_LEN + 1];
    let overlong_error = Ikev2CertReqSubjectPublicKeyInfo::from_der(&overlong)
        .expect_err("overlong input must fail before DER parsing");
    assert_eq!(
        overlong_error,
        Ikev2CertReqSubjectPublicKeyInfoError::TooLong
    );
}

fn protected_prefix(body_len: usize) -> Vec<u8> {
    let payload_len = u16::try_from(4 + body_len).expect("payload length");
    let message_len = u32::try_from(32 + body_len).expect("message length");
    let mut prefix = Vec::with_capacity(32);
    prefix.extend_from_slice(&1_u64.to_be_bytes());
    prefix.extend_from_slice(&2_u64.to_be_bytes());
    prefix.extend_from_slice(&[46, 0x20, 35, 0x20]);
    prefix.extend_from_slice(&7_u32.to_be_bytes());
    prefix.extend_from_slice(&message_len.to_be_bytes());
    prefix.extend_from_slice(&[35, 0]);
    prefix.extend_from_slice(&payload_len.to_be_bytes());
    prefix
}

fn protected_header(body_len: usize) -> Header {
    Header {
        initiator_spi: 1,
        responder_spi: 2,
        next_payload: PayloadType::Encrypted.as_u8(),
        major_version: 2,
        minor_version: 0,
        exchange_type: 35,
        flags: HeaderFlags::new(0x20),
        message_id: 7,
        length: u32::try_from(32 + body_len).expect("message length"),
    }
}

fn assert_module_failure(error: Ikev2SaInitCryptoError, code: Ikev2CryptoModuleErrorCode) {
    match error {
        Ikev2SaInitCryptoError::CryptoModuleFailure { error } => assert_eq!(error.code(), code),
        other => panic!("expected module failure, got {other:?}"),
    }
}

fn assert_protected_module_failure(
    error: Ikev2ProtectedPayloadCryptoError,
    code: Ikev2CryptoModuleErrorCode,
) {
    match error {
        Ikev2ProtectedPayloadCryptoError::CryptoModuleFailure { error } => {
            assert_eq!(error.code(), code);
        }
        other => panic!("expected protected-payload module failure, got {other:?}"),
    }
}

#[test]
fn one_admitted_module_handles_every_operation_and_withdrawal_never_falls_back() {
    let profile = profile();
    let requirements = requirements(profile);
    let module = Arc::new(CountingModule::new());
    let module_object: Arc<dyn IkeCryptoModule> = module.clone();

    let missing_policy = block_on(install_ikev2_crypto_module(
        Arc::clone(&module_object),
        ProviderPolicy::new(),
        requirements.clone(),
    ))
    .expect_err("policy must name every derived capability");
    assert!(matches!(
        missing_policy,
        Ikev2CryptoModuleInstallError::PolicyMissingCapabilities { .. }
    ));
    assert_not_installed();

    module.reject_prf_support.store(true, Ordering::SeqCst);
    let unsupported = block_on(install_ikev2_crypto_module(
        Arc::clone(&module_object),
        policy(&requirements),
        requirements.clone(),
    ))
    .expect_err("unsupported configured algorithm must fail preflight");
    assert!(matches!(
        unsupported,
        Ikev2CryptoModuleInstallError::AlgorithmUnsupported { .. }
    ));
    module.reject_prf_support.store(false, Ordering::SeqCst);
    assert_not_installed();

    module.reject_hash_support.store(true, Ordering::SeqCst);
    let unsupported_hash = block_on(install_ikev2_crypto_module(
        Arc::clone(&module_object),
        policy(&requirements),
        requirements.clone(),
    ))
    .expect_err("unsupported configured CERTREQ SHA-1 must fail preflight");
    assert!(matches!(
        unsupported_hash,
        Ikev2CryptoModuleInstallError::AlgorithmUnsupported { algorithm: "sha1" }
    ));
    module.reject_hash_support.store(false, Ordering::SeqCst);
    assert_not_installed();

    module.identity_reads.store(0, Ordering::SeqCst);
    module
        .drift_identity_after_first_read
        .store(true, Ordering::SeqCst);
    let drift = block_on(install_ikev2_crypto_module(
        Arc::clone(&module_object),
        policy(&requirements),
        requirements.clone(),
    ))
    .expect_err("evidence drift must fail before installation");
    assert_eq!(drift, Ikev2CryptoModuleInstallError::EvidenceChanged);
    module
        .drift_identity_after_first_read
        .store(false, Ordering::SeqCst);
    assert_not_installed();

    let all = module.capabilities();
    module.set_serviceable(all);
    module.readiness_reads.store(0, Ordering::SeqCst);
    module
        .withdraw_extra_after_first_readiness
        .store(true, Ordering::SeqCst);
    let extra_evidence_drift = block_on(install_ikev2_crypto_module(
        Arc::clone(&module_object),
        policy(&requirements),
        requirements.clone(),
    ))
    .expect_err("policy-superset capability withdrawal must fail installation");
    assert_eq!(
        extra_evidence_drift,
        Ikev2CryptoModuleInstallError::EvidenceChanged
    );
    module
        .withdraw_extra_after_first_readiness
        .store(false, Ordering::SeqCst);
    module.set_serviceable(all);
    assert_not_installed();

    let report = block_on(install_ikev2_crypto_module(
        module_object,
        policy(&requirements),
        requirements.clone(),
    ))
    .expect("coherent module admits exactly once");
    assert!(report
        .effective_capabilities()
        .contains_all(requirements.required_capabilities()));

    let before_pre_admission_inspection = module.counts.snapshot();
    let inspection = inspect_ikev2_signature_key_pkcs8_der(P256_PKCS8_DER)
        .expect("inspection remains independent after module installation");
    assert_eq!(
        inspection.requirement().algorithm(),
        IkeSignatureAlgorithm::EcdsaP256Sha2_256
    );
    assert_eq!(
        module.counts.snapshot(),
        before_pre_admission_inspection,
        "pre-admission inspection must dispatch no module operation"
    );

    ikev2_nat_detection_hash(1, 2, "192.0.2.10:500".parse().expect("synthetic endpoint"))
        .expect("NAT hash routed");
    let certreq_spki =
        Ikev2CertReqSubjectPublicKeyInfo::from_der(P256_SPKI_DER).expect("synthetic SPKI is valid");
    let certreq_hash = ikev2_certreq_authority_key_hash(certreq_spki).expect("CERTREQ hash routed");
    assert_eq!(certreq_hash.as_bytes(), &P256_SPKI_SHA1);
    assert_eq!(
        format!("{certreq_hash:?}"),
        "Ikev2CertReqAuthorityHash { len: 20 }"
    );
    let hash_count = module.counts.hash.load(Ordering::SeqCst);
    for malformed_container in [
        spki_with_extra_outer_element(),
        spki_with_extra_algorithm_identifier_element(),
    ] {
        let error = Ikev2CertReqSubjectPublicKeyInfo::from_der(&malformed_container)
            .expect_err("malformed SPKI must fail before provider dispatch");
        assert_eq!(error, Ikev2CertReqSubjectPublicKeyInfoError::MalformedDer);
    }
    assert_eq!(module.counts.hash.load(Ordering::SeqCst), hash_count);
    let material = derive_ike_sa_init_key_material(
        profile,
        1_u64.to_be_bytes(),
        2_u64.to_be_bytes(),
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 32],
        None,
    )
    .expect("PRF and PRF+ routed");
    protocol_key_uses_only_admitted_prf(&module, profile, &material);
    let cleartext = [0_u8, 0, 0, 4];
    let body_len = ikev2_aes_cbc_protected_body_len(profile, cleartext.len())
        .expect("CBC protected body length");
    let prefix = protected_prefix(body_len);
    let cbc_body = seal_ikev2_sa_init_aes_cbc_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: &prefix,
        },
        &cleartext,
    )
    .expect("entropy, CBC, and integrity routed");

    let aead_profile = aead_profile();
    let aead_material = derive_ike_sa_init_key_material(
        aead_profile,
        1_u64.to_be_bytes(),
        2_u64.to_be_bytes(),
        &[0x71; 32],
        &[0x72; 32],
        &[0x73; 32],
        None,
    )
    .expect("AEAD profile PRF and PRF+ routed");
    let aead_body_len =
        ikev2_aes_gcm_protected_body_len(cleartext.len(), 0).expect("AEAD body length");
    let aead_prefix = protected_prefix(aead_body_len);
    let aead_body = seal_ikev2_sa_init_protected_payload(
        aead_profile,
        &aead_material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: &aead_prefix,
        },
        &cleartext,
        0,
        [0x44; 8],
    )
    .expect("AEAD seal routed");

    let left = Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Ecp256).expect("left DH handle");
    let right = Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Ecp256).expect("right DH handle");
    left.agree(right.public_value())
        .expect("DH agreement routed");

    let key = Ikev2SignatureAuthKey::ecdsa_p256_pkcs8_der(P256_PKCS8_DER)
        .expect("signing key loaded through module");
    let identity = [0x44; 8];
    let (sa_init_request, sa_init_response, signing_authority, verification_authority) =
        signature_hash_authorities();
    let signed_octets = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message: &sa_init_response,
        peer_nonce: &[0x66; 32],
        identity_payload_body: &identity,
    };
    let auth_data = compute_ike_auth_signature(
        profile,
        &material,
        signed_octets,
        &key,
        Some(
            signing_authority
                .for_exchange(&sa_init_request, &sa_init_response)
                .expect("signing authority matches test exchange"),
        ),
    )
    .expect("signing routed");
    let public =
        Ikev2SignaturePublicKey::from_spki_der(P256_SPKI_DER).expect("synthetic verification key");
    verify_ike_auth_signature(
        profile,
        &material,
        signed_octets,
        &public,
        &Ikev2AuthenticationPayload {
            auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
            auth_data: &auth_data,
        },
        Some(
            verification_authority
                .for_exchange(&sa_init_request, &sa_init_response)
                .expect("verification authority matches test exchange"),
        ),
    )
    .expect("verification routed");

    let before_nonce_mismatch = module.counts.snapshot();
    let opposite_direction_nonce = Ikev2IkeAuthSignedOctets {
        peer_nonce: support::TEST_RESPONDER_NONCE,
        ..signed_octets
    };
    assert_eq!(
        compute_ike_auth_signature(
            profile,
            &material,
            opposite_direction_nonce,
            &key,
            Some(
                signing_authority
                    .for_exchange(&sa_init_request, &sa_init_response)
                    .expect("signing authority matches test exchange"),
            ),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch)
    );
    assert_eq!(
        verify_ike_auth_signature(
            profile,
            &material,
            opposite_direction_nonce,
            &public,
            &Ikev2AuthenticationPayload {
                auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
                auth_data: &auth_data,
            },
            Some(
                verification_authority
                    .for_exchange(&sa_init_request, &sa_init_response)
                    .expect("verification authority matches test exchange"),
            ),
        ),
        Err(Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch)
    );
    assert_eq!(
        module.counts.snapshot(),
        before_nonce_mismatch,
        "nonce mismatch must fail before PRF, signing, or verification dispatch"
    );

    let local_authorization = signing_authority
        .authorize_local_auth_self_verification(
            &sa_init_request,
            &sa_init_response,
            signed_octets,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("exact local self-verification authorization");
    verify_local_ike_auth_signature(
        profile,
        &material,
        &Ikev2AuthenticationPayload {
            auth_method: IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE,
            auth_data: &auth_data,
        },
        local_authorization,
    )
    .expect("local self-verification routed");

    let before_local_rejections = module.counts.snapshot();
    let wrong_local_nonce = Ikev2IkeAuthSignedOctets {
        peer_nonce: support::TEST_RESPONDER_NONCE,
        ..signed_octets
    };
    assert_eq!(
        signing_authority
            .authorize_local_auth_self_verification(
                &sa_init_request,
                &sa_init_response,
                wrong_local_nonce,
                Ikev2SignatureHashAlgorithm::Sha2_256,
                &public,
            )
            .expect_err("wrong local nonce must fail before authorization"),
        Ikev2IkeAuthVerificationError::SignatureHashAuthorityExchangeMismatch
    );
    let method_substitution_authorization = signing_authority
        .authorize_local_auth_self_verification(
            &sa_init_request,
            &sa_init_response,
            signed_octets,
            Ikev2SignatureHashAlgorithm::Sha2_256,
            &public,
        )
        .expect("exact local self-verification authorization");
    assert_eq!(
        verify_local_ike_auth_signature(
            profile,
            &material,
            &Ikev2AuthenticationPayload {
                auth_method: 1,
                auth_data: &auth_data,
            },
            method_substitution_authorization,
        ),
        Err(Ikev2IkeAuthVerificationError::UnsupportedAuthenticationMethod { method: 1 })
    );
    assert_eq!(
        module.counts.snapshot(),
        before_local_rejections,
        "local authority and method rejection must precede PRF or signature dispatch"
    );

    let unadmitted_profile = Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesCbc128,
        Ikev2IntegrityAlgorithm::HmacSha2_256_128,
    )
    .expect("unadmitted algorithm still forms an executable profile");
    let prf_count = module.counts.prf.load(Ordering::SeqCst);
    assert_module_failure(
        derive_ike_sa_init_key_material(
            unadmitted_profile,
            1_u64.to_be_bytes(),
            2_u64.to_be_bytes(),
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            None,
        )
        .expect_err("supported but unconfigured PRF must not execute"),
        Ikev2CryptoModuleErrorCode::AlgorithmNotAdmitted,
    );
    assert_eq!(module.counts.prf.load(Ordering::SeqCst), prf_count);

    module.reject_prf_support.store(true, Ordering::SeqCst);
    assert_module_failure(
        derive_ike_sa_init_key_material(
            profile,
            1_u64.to_be_bytes(),
            2_u64.to_be_bytes(),
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            None,
        )
        .expect_err("withdrawn algorithm support must fail before dispatch"),
        Ikev2CryptoModuleErrorCode::AlgorithmUnsupported,
    );
    assert_eq!(module.counts.prf.load(Ordering::SeqCst), prf_count);
    module.reject_prf_support.store(false, Ordering::SeqCst);

    let hash_count = module.counts.hash.load(Ordering::SeqCst);
    module.reject_hash_support.store(true, Ordering::SeqCst);
    let unsupported_hash = ikev2_certreq_authority_key_hash(certreq_spki)
        .expect_err("withdrawn SHA-1 support must fail before dispatch");
    assert_eq!(
        unsupported_hash.code(),
        Ikev2CryptoModuleErrorCode::AlgorithmUnsupported
    );
    assert_eq!(module.counts.hash.load(Ordering::SeqCst), hash_count);
    module.reject_hash_support.store(false, Ordering::SeqCst);

    module.fail_hash_operation.store(true, Ordering::SeqCst);
    let operation_error = ikev2_certreq_authority_key_hash(certreq_spki)
        .expect_err("provider hash failure must remain typed and redacted");
    assert_eq!(
        operation_error.code(),
        Ikev2CryptoModuleErrorCode::OperationFailed
    );
    assert_eq!(
        operation_error.operation_code(),
        Some(CryptoOperationErrorCode::OperationFailed)
    );
    assert!(!format!("{operation_error}").contains(module.provider_diagnostic));
    assert!(!format!("{operation_error:?}").contains(module.provider_diagnostic));
    module.fail_hash_operation.store(false, Ordering::SeqCst);

    let hash_count = module.counts.hash.load(Ordering::SeqCst);
    module.drift_validation.store(true, Ordering::SeqCst);
    let validation_error = ikev2_certreq_authority_key_hash(certreq_spki)
        .expect_err("validation declaration drift must fail before dispatch");
    assert_eq!(
        validation_error.code(),
        Ikev2CryptoModuleErrorCode::ValidationChanged
    );
    assert_eq!(module.counts.hash.load(Ordering::SeqCst), hash_count);
    module.drift_validation.store(false, Ordering::SeqCst);

    module.identity_reads.store(1, Ordering::SeqCst);
    module
        .drift_identity_after_first_read
        .store(true, Ordering::SeqCst);
    let identity_error = ikev2_certreq_authority_key_hash(certreq_spki)
        .expect_err("module identity drift must fail before dispatch");
    assert_eq!(
        identity_error.code(),
        Ikev2CryptoModuleErrorCode::IdentityChanged
    );
    assert_eq!(module.counts.hash.load(Ordering::SeqCst), hash_count);
    module
        .drift_identity_after_first_read
        .store(false, Ordering::SeqCst);

    // A module's successful return is still untrusted shape-wise. Every
    // algorithm-derived width and every opaque-DH shape is rejected at the
    // routed boundary before malformed bytes can reach protocol consumers.
    module.set_malformed_output(MalformedOutput::Hash);
    let hash_error = ikev2_certreq_authority_key_hash(certreq_spki)
        .expect_err("wrong-length successful hash output must fail closed");
    assert_eq!(hash_error.code(), Ikev2CryptoModuleErrorCode::InvalidOutput);
    assert!(!format!("{hash_error}").contains("hostile-provider-output-marker"));
    assert!(!format!("{hash_error:?}").contains("hostile-provider-output-marker"));
    module.set_malformed_output(MalformedOutput::None);

    module.set_malformed_output(MalformedOutput::Prf);
    assert_module_failure(
        derive_ike_sa_init_key_material(
            profile,
            1_u64.to_be_bytes(),
            2_u64.to_be_bytes(),
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            None,
        )
        .expect_err("short successful PRF output must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    module.set_malformed_output(MalformedOutput::PrfPlus);
    assert_module_failure(
        derive_ike_sa_init_key_material(
            profile,
            1_u64.to_be_bytes(),
            2_u64.to_be_bytes(),
            &[0x11; 32],
            &[0x22; 32],
            &[0x33; 32],
            None,
        )
        .expect_err("short successful PRF+ output must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    module.set_malformed_output(MalformedOutput::None);

    module.set_malformed_output(MalformedOutput::CbcEncrypt);
    assert_protected_module_failure(
        seal_ikev2_sa_init_aes_cbc_protected_payload(
            profile,
            &material,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
            ProtectedPayloadSealContext {
                kind: ProtectedPayloadKind::Encrypted,
                message_prefix: &prefix,
            },
            &cleartext,
        )
        .expect_err("short successful CBC ciphertext must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    module.set_malformed_output(MalformedOutput::Integrity);
    assert_protected_module_failure(
        seal_ikev2_sa_init_aes_cbc_protected_payload(
            profile,
            &material,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
            ProtectedPayloadSealContext {
                kind: ProtectedPayloadKind::Encrypted,
                message_prefix: &prefix,
            },
            &cleartext,
        )
        .expect_err("short successful integrity output must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    module.set_malformed_output(MalformedOutput::AeadSeal);
    assert_protected_module_failure(
        seal_ikev2_sa_init_protected_payload(
            aead_profile,
            &aead_material,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
            ProtectedPayloadSealContext {
                kind: ProtectedPayloadKind::Encrypted,
                message_prefix: &aead_prefix,
            },
            &cleartext,
            0,
            [0x45; 8],
        )
        .expect_err("short successful AEAD body must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    module.set_malformed_output(MalformedOutput::AeadSealWrongExplicitIv);
    assert_protected_module_failure(
        seal_ikev2_sa_init_protected_payload(
            aead_profile,
            &aead_material,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
            ProtectedPayloadSealContext {
                kind: ProtectedPayloadKind::Encrypted,
                message_prefix: &aead_prefix,
            },
            &cleartext,
            0,
            [0x46; 8],
        )
        .expect_err("correct-length AEAD body with a substituted explicit IV must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    module.set_malformed_output(MalformedOutput::None);

    let mut aead_message = aead_prefix.clone();
    aead_message.extend_from_slice(&aead_body);
    let aead_header = protected_header(aead_body.len());
    module.set_malformed_output(MalformedOutput::AeadOpen);
    assert_protected_module_failure(
        decrypt_ikev2_sa_init_protected_payload(
            aead_profile,
            &aead_material,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
            ProtectedPayloadContext {
                header: &aead_header,
                kind: ProtectedPayloadKind::Encrypted,
                first_inner_payload: PayloadType::IdentificationInitiator,
                payload_offset: 0,
                message_bytes: &aead_message,
            },
            &aead_body,
        )
        .expect_err("short successful AEAD plaintext must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );

    let mut cbc_message = prefix.clone();
    cbc_message.extend_from_slice(&cbc_body);
    let cbc_header = protected_header(cbc_body.len());
    module.set_malformed_output(MalformedOutput::CbcDecrypt);
    assert_protected_module_failure(
        decrypt_ikev2_sa_init_protected_payload(
            profile,
            &material,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
            ProtectedPayloadContext {
                header: &cbc_header,
                kind: ProtectedPayloadKind::Encrypted,
                first_inner_payload: PayloadType::IdentificationInitiator,
                payload_offset: 0,
                message_bytes: &cbc_message,
            },
            &cbc_body,
        )
        .expect_err("short successful CBC plaintext must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );

    module.set_malformed_output(MalformedOutput::DhGroup);
    assert_module_failure(
        Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Ecp256)
            .expect_err("wrong successful DH handle group must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    module.set_malformed_output(MalformedOutput::DhPublic);
    assert_module_failure(
        Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Ecp256)
            .expect_err("short successful DH public value must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    module.set_malformed_output(MalformedOutput::DhSemanticPublic);
    assert_module_failure(
        Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Ecp256)
            .expect_err("off-curve successful DH public value must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    let valid_peer_public = right.public_value().to_vec();
    let agree_count = module.counts.dh_agree.load(Ordering::SeqCst);
    assert_module_failure(
        left.agree(&valid_peer_public)
            .expect_err("DH handle public-value drift must fail before agreement"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    assert_eq!(module.counts.dh_agree.load(Ordering::SeqCst), agree_count);
    module.set_malformed_output(MalformedOutput::None);

    let invalid_peer_public = [0_u8; 64];
    let agree_count = module.counts.dh_agree.load(Ordering::SeqCst);
    assert!(matches!(
        left.agree(&invalid_peer_public),
        Err(Ikev2SaInitCryptoError::InvalidPeerPublicKey {
            group: Ikev2DhGroup::Ecp256,
            actual_len: 64,
        })
    ));
    assert_eq!(module.counts.dh_agree.load(Ordering::SeqCst), agree_count);

    module.set_malformed_output(MalformedOutput::DhAgree);
    assert_module_failure(
        left.agree(right.public_value())
            .expect_err("short successful DH shared secret must fail closed"),
        Ikev2CryptoModuleErrorCode::InvalidOutput,
    );
    module.set_malformed_output(MalformedOutput::None);

    let sign_count = module.counts.signature_sign.load(Ordering::SeqCst);
    module.set_malformed_output(MalformedOutput::SigningAlgorithm);
    let error = compute_ike_auth_signature(
        profile,
        &material,
        signed_octets,
        &key,
        Some(
            signing_authority
                .for_exchange(&sa_init_request, &sa_init_response)
                .expect("signing authority matches test exchange"),
        ),
    )
    .expect_err("signing-handle algorithm drift must fail before signing");
    assert!(matches!(
        error,
        Ikev2IkeAuthVerificationError::CryptoModuleFailure { error }
            if error.code() == Ikev2CryptoModuleErrorCode::InvalidOutput
    ));
    assert_eq!(
        module.counts.signature_sign.load(Ordering::SeqCst),
        sign_count
    );
    module.set_malformed_output(MalformedOutput::None);

    for (malformed_output, failure) in [
        (
            MalformedOutput::SigningEmpty,
            "empty successful ECDSA signature must fail closed",
        ),
        (
            MalformedOutput::SigningMalformedDer,
            "malformed successful ECDSA DER signature must fail closed",
        ),
        (
            MalformedOutput::SigningOutOfRange,
            "out-of-range successful ECDSA scalar must fail closed",
        ),
    ] {
        module.set_malformed_output(malformed_output);
        let error = compute_ike_auth_signature(
            profile,
            &material,
            signed_octets,
            &key,
            Some(
                signing_authority
                    .for_exchange(&sa_init_request, &sa_init_response)
                    .expect("signing authority matches test exchange"),
            ),
        )
        .expect_err(failure);
        assert!(matches!(
            error,
            Ikev2IkeAuthVerificationError::CryptoModuleFailure { error }
                if error.code() == Ikev2CryptoModuleErrorCode::InvalidOutput
        ));
    }
    module.set_malformed_output(MalformedOutput::None);

    #[cfg(feature = "rsa-signing")]
    {
        let rsa_key = Ikev2SignatureAuthKey::rsa_pkcs8_der(
            opc_proto_ikev2::Ikev2SignatureAuthMethod::RsaDigitalSignature,
            RSA2048_PKCS8_DER,
        )
        .expect("RSA signing key loads through the admitted module");
        module.set_malformed_output(MalformedOutput::SigningRsaWrongWidth);
        let error = compute_ike_auth_signature(profile, &material, signed_octets, &rsa_key, None)
            .expect_err("wrong-width successful RSA signature must fail closed");
        assert!(matches!(
            error,
            Ikev2IkeAuthVerificationError::CryptoModuleFailure { error }
                if error.code() == Ikev2CryptoModuleErrorCode::InvalidOutput
        ));
        module.set_malformed_output(MalformedOutput::None);
    }

    let routed = module.counts.snapshot();
    assert!(routed.iter().all(|count| *count > 0), "{routed:?}");

    module.set_serviceable(all.without(CryptoCapability::SealedKeyStorage));
    let before = module.counts.snapshot();
    let error = ikev2_certreq_authority_key_hash(certreq_spki)
        .expect_err("withdrawn non-IKE policy capability must fail every operation");
    assert_eq!(
        error.code(),
        Ikev2CryptoModuleErrorCode::CapabilityWithdrawn
    );
    assert_eq!(module.counts.snapshot(), before);
    module.set_serviceable(all);

    module.set_advertised(all.without(CryptoCapability::IkeHash));
    let before = module.counts.snapshot();
    let error = ikev2_certreq_authority_key_hash(certreq_spki)
        .expect_err("withdrawn advertised capability must fail");
    assert_eq!(
        error.code(),
        Ikev2CryptoModuleErrorCode::CapabilityWithdrawn
    );
    assert_eq!(module.counts.snapshot(), before);
    module.set_advertised(all);

    module.set_serviceable(all.without(CryptoCapability::Zeroization));
    let before = module.counts.snapshot();
    let error =
        ikev2_nat_detection_hash(1, 2, "192.0.2.10:500".parse().expect("synthetic endpoint"))
            .expect_err("supporting-capability withdrawal must fail every operation");
    assert_eq!(
        error.code(),
        Ikev2CryptoModuleErrorCode::CapabilityWithdrawn
    );
    assert_eq!(module.counts.snapshot(), before);
    module.set_serviceable(all);

    let agree_count = module.counts.dh_agree.load(Ordering::SeqCst);
    module.set_serviceable(all.without(CryptoCapability::IkeDiffieHellman));
    assert_module_failure(
        left.agree(right.public_value())
            .expect_err("withdrawn DH handle must not execute"),
        Ikev2CryptoModuleErrorCode::CapabilityWithdrawn,
    );
    assert_eq!(module.counts.dh_agree.load(Ordering::SeqCst), agree_count);
    module.set_serviceable(all);

    let sign_count = module.counts.signature_sign.load(Ordering::SeqCst);
    module.withdraw_signature_after_next_prf();
    let error = compute_ike_auth_signature(
        profile,
        &material,
        signed_octets,
        &key,
        Some(
            signing_authority
                .for_exchange(&sa_init_request, &sa_init_response)
                .expect("signing authority matches test exchange"),
        ),
    )
    .expect_err("signature withdrawal between transcript PRF and handle use must fail");
    assert!(matches!(
        error,
        Ikev2IkeAuthVerificationError::CryptoModuleFailure { error }
            if error.code() == Ikev2CryptoModuleErrorCode::CapabilityWithdrawn
    ));
    assert_eq!(
        module.counts.signature_sign.load(Ordering::SeqCst),
        sign_count
    );

    module.set_serviceable(all);
    let duplicate_module: Arc<dyn IkeCryptoModule> = module.clone();
    let duplicate = block_on(install_ikev2_crypto_module(
        duplicate_module,
        policy(&requirements),
        requirements,
    ))
    .expect_err("the installed process slot must be immutable");
    assert_eq!(duplicate, Ikev2CryptoModuleInstallError::AlreadyInstalled);
    initiating_sync_uses_admitted_entropy_and_rechecks_runtime_readiness(&module);
}

fn initiating_sync_uses_admitted_entropy_and_rechecks_runtime_readiness(module: &CountingModule) {
    use opc_proto_ikev2::{
        recovery::{
            Ikev2CommittedWindow as Window, Ikev2CommittedWindowRecord as Record,
            Ikev2SyncClock as Clock, Ikev2SyncDisposition as Disposition,
            Ikev2SyncInitiatorAction as Action, Ikev2SyncRecoveryPolicy as SyncPolicy,
            Ikev2SyncResponderRecord as SyncRecord, Ikev2WindowError as Error,
        },
        Ikev2AesGcmIvAllocator as Allocator, Ikev2AesGcmIvLimits as Limits,
        Ikev2AesGcmIvPurpose as Purpose, Ikev2AesGcmIvRecord as IvRecord,
        Ikev2MessageIdSyncAgreement as Agreement, Ikev2MessageIdSyncMode as Mode,
        Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa, Ikev2SaInitKeyMaterial as Keys,
    };
    let profile = aead_profile();
    let keys = Keys::from_established_keys(
        profile,
        false,
        &[0x11; 32],
        &[],
        &[],
        &[0x41; 20],
        &[0x62; 20],
        &[0x22; 32],
        &[0x33; 32],
    )
    .unwrap();
    let domain = support::window_domain(
        1,
        2,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        profile,
        &keys,
    )
    .unwrap();
    let initial = Record::initial(domain.clone(), 1, 1);
    let iv_record = IvRecord::from_persisted(
        support::epoch_inputs(
            1,
            2,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
            profile,
            &keys,
        ),
        Limits::new(128, 2, 1, 2).unwrap(),
        0,
        Some(1),
    )
    .unwrap();
    let window = Window::restore(&domain, profile, &keys, &initial, &iv_record).unwrap();
    let all = module.capabilities();
    for capability in [
        CryptoCapability::ApprovedEntropy,
        CryptoCapability::IkeEncryption,
    ] {
        let mut negotiation = window.sync_readiness(profile, &keys).unwrap().negotiate();
        let before = module.counts.snapshot();
        module.set_serviceable(all.without(capability));
        assert!(matches!(
            window.sync_readiness(profile, &keys),
            Err(Error::SyncUnavailable)
        ));
        assert!(matches!(
            negotiation.local_offer(),
            Err(Error::SyncUnavailable)
        ));
        assert_eq!(module.counts.snapshot(), before);
        module.set_serviceable(all);
    }
    let unadmitted = Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_256,
    )
    .unwrap();
    let other_keys = Keys::from_established_keys(
        unadmitted,
        false,
        &[0x11; 32],
        &[],
        &[],
        &[0x41; 36],
        &[0x62; 36],
        &[0x22; 32],
        &[0x33; 32],
    )
    .unwrap();
    let other_domain = support::window_domain(
        1,
        2,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        unadmitted,
        &other_keys,
    )
    .unwrap();
    let other_record = Record::initial(other_domain.clone(), 1, 1);
    let other_iv = IvRecord::from_persisted(
        support::epoch_inputs(
            1,
            2,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
            unadmitted,
            &other_keys,
        ),
        iv_record.limits(),
        0,
        Some(1),
    )
    .unwrap();
    let other = Window::restore(
        &other_domain,
        unadmitted,
        &other_keys,
        &other_record,
        &other_iv,
    )
    .unwrap();
    assert!(matches!(
        other.sync_readiness(unadmitted, &other_keys),
        Err(Error::SyncUnavailable)
    ));
    let agreement =
        Agreement::from_persisted(Sa::new(1, 2, Role::Initiator).unwrap(), Mode::Negotiated);
    let original = initial
        .with_sync_state(
            SyncRecord::from_persisted(agreement, None, None, None, None, Disposition::Continue, 0)
                .unwrap(),
        )
        .unwrap();
    let mut allocator = Allocator::restore(domain.send_iv_domain(), &iv_record).unwrap();
    let block = allocator.prepare(8, Purpose::Ordinary).unwrap();
    let iv_record = block.record().clone();
    block.activate_after_commit(&iv_record).unwrap();
    let policy = SyncPolicy::new(42, Clock::new(100, 7), 200, 3, 10).unwrap();
    // Withdrawal makes zero provider calls; provider failure is exactly one admitted call.
    for fail_provider in [false, true] {
        let mut window = Window::restore(&domain, profile, &keys, &original, &iv_record).unwrap();
        let admitted = window.begin_sync(policy, Clock::new(100, 7), None).unwrap();
        if fail_provider {
            module.sync_entropy_mode.store(2, Ordering::SeqCst);
        } else {
            module.set_serviceable(all.without(CryptoCapability::ApprovedEntropy));
        }
        let before = module.counts.snapshot();
        assert!(matches!(
            admitted.prepare(
                profile,
                &keys,
                allocator.allocate(Purpose::Ordinary).unwrap()
            ),
            Err(Error::SyncEntropy)
        ));
        let after = module.counts.snapshot();
        assert_eq!(after[1] - before[1], usize::from(fail_provider));
        assert_eq!(after[4], before[4]);
        assert_eq!(window.record(), &original);
        assert!(matches!(
            window.replay_request(),
            Err(Error::CommitUncertain)
        ));
        module.set_serviceable(all);
        module.sync_entropy_mode.store(0, Ordering::SeqCst);
    }
    let mut window = Window::restore(&domain, profile, &keys, &original, &iv_record).unwrap();
    module.sync_entropy_mode.store(1, Ordering::SeqCst);
    for (index, byte) in [(0, 0xa5), (1, 0xb6)] {
        let now = Clock::new(100 + index * 10, 7);
        module.sync_entropy_byte.store(byte, Ordering::SeqCst);
        let before = module.counts.snapshot();
        let admitted = if index == 0 {
            window.begin_sync(policy, now, None).unwrap()
        } else {
            window.retry_sync(now).unwrap()
        };
        let prepared = admitted
            .prepare(
                profile,
                &keys,
                allocator.allocate(Purpose::Ordinary).unwrap(),
            )
            .unwrap();
        let record = prepared.record().clone();
        assert_eq!(
            record
                .sync_recovery()
                .unwrap()
                .pending()
                .unwrap()
                .notification()
                .nonce(),
            [byte; 4]
        );
        let token = prepared.commit_after_durable(&record, now).unwrap();
        assert!(matches!(
            window.release_sync_action(token, now).unwrap(),
            Action::SendRequest(_)
        ));
        let after = module.counts.snapshot();
        assert_eq!(after[1] - before[1], 1);
        assert_eq!(after[4] - before[4], 1);
    }
    let stored = window.record().clone();
    module.sync_entropy_byte.store(0xa5, Ordering::SeqCst); // First, not merely latest nonce.
    let before = module.counts.snapshot();
    let admitted = window.retry_sync(Clock::new(120, 7)).unwrap();
    assert!(matches!(
        admitted.prepare(
            profile,
            &keys,
            allocator.allocate(Purpose::Ordinary).unwrap()
        ),
        Err(Error::SyncEntropy)
    ));
    let after = module.counts.snapshot();
    assert_eq!(after[1] - before[1], 4);
    assert_eq!(after[4], before[4]);
    assert_eq!(window.record(), &stored);
    assert!(matches!(
        window.replay_request(),
        Err(Error::CommitUncertain)
    ));
    let mut restored = Window::restore(&domain, profile, &keys, &stored, &iv_record).unwrap();
    module.sync_entropy_byte.store(0xc7, Ordering::SeqCst);
    let prepared = restored
        .retry_sync(Clock::new(120, 7))
        .unwrap()
        .prepare(
            profile,
            &keys,
            allocator.allocate(Purpose::Ordinary).unwrap(),
        )
        .unwrap();
    assert_eq!(
        prepared.record().sync_recovery().unwrap().attempts().len(),
        3
    );
    assert_eq!(
        prepared
            .record()
            .sync_recovery()
            .unwrap()
            .pending()
            .unwrap()
            .notification()
            .nonce(),
        [0xc7; 4]
    );
    module.sync_entropy_mode.store(0, Ordering::SeqCst);
}

#[test]
fn canonical_module_policy_faults_and_process_restart() {
    use std::{collections::BTreeMap, fs, process::Command};
    let directory =
        std::env::temp_dir().join(format!("ike-canonical-monitor-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let mut transcripts = BTreeMap::new();
    let mut repeated = 0;
    for case in [
        "not-installed",
        "wrong-kat",
        "validated",
        "faults",
        "recreation",
        "readiness",
        "concurrency",
        "interruption",
        "mixed-before",
        "mixed-after",
    ] {
        let trace = directory.join(case);
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "canonical_module_child", "--nocapture"])
            .env("OPC_CANONICAL_MODULE_CASE", case)
            .env("OPC_CANONICAL_TRANSCRIPT_PATH", &trace)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "case {case}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if case.starts_with("mixed-") {
            let entries = fs::read_to_string(&trace).unwrap();
            for line in entries.lines() {
                let (key_nonce, inputs) = line.split_once(' ').unwrap();
                if let Some(old) = transcripts.insert(key_nonce.to_owned(), inputs.to_owned()) {
                    assert_eq!(old, inputs, "cross-process (K,N) maps to different (A,P)");
                    repeated += 1;
                }
            }
            fs::remove_file(trace).unwrap();
        }
    }
    assert!(
        transcripts.len() > 100,
        "monitor includes actual ordinary/sync/canonical inputs"
    );
    assert!(
        repeated >= 12,
        "restart must actually reevaluate canonical nonces"
    );
    fs::remove_dir(directory).unwrap();
}

#[test]
fn canonical_module_child() {
    use canonical_fixtures::{Fixture, ALGORITHMS, DIRECTIONS};
    use opc_proto_ikev2::canonical::{
        Ikev2CanonicalEmptyReplies as Canonical, Ikev2CanonicalError as Error,
        Ikev2CanonicalPolicy as Policy,
    };
    let Ok(case) = std::env::var("OPC_CANONICAL_MODULE_CASE") else {
        return;
    };
    if case == "not-installed" {
        assert_eq!(
            Canonical::preflight(ALGORITHMS[0], Policy::default()),
            Err(Error::Unavailable)
        );
        return;
    }
    let module = Arc::new(CountingModule::new());
    module
        .drift_validation
        .store(case == "validated", Ordering::SeqCst);
    let requirements = Ikev2CryptoRequirements::all_software_supported();
    let _report = block_on(install_ikev2_crypto_module(
        module.clone(),
        policy(&requirements),
        requirements,
    ))
    .unwrap();
    if case == "wrong-kat" {
        module.canonical_fault.store(6, Ordering::SeqCst);
        module.canonical_failures.store(100, Ordering::SeqCst);
        // A consistently wrong implementation can pass its own round trip.
        let body = module
            .seal_aead(
                IkeAeadAlgorithm::AesGcm16_128,
                &[0; 16],
                &[1; 4],
                &[0xff; 8],
                &[0; 32],
                &[0],
            )
            .unwrap();
        assert_eq!(
            *module
                .open_aead(
                    IkeAeadAlgorithm::AesGcm16_128,
                    &[0; 16],
                    &[1; 4],
                    &[0; 32],
                    &body
                )
                .unwrap(),
            [0]
        );
        assert_eq!(
            Canonical::preflight(ALGORITHMS[0], Policy::default()),
            Err(Error::QualificationFailed)
        );
        let calls = module.canonical_seals.load(Ordering::SeqCst);
        module.canonical_fault.store(0, Ordering::SeqCst);
        module.canonical_failures.store(0, Ordering::SeqCst);
        assert_eq!(
            Canonical::preflight(ALGORITHMS[0], Policy::default()),
            Err(Error::QualificationFailed)
        );
        assert_eq!(
            module.canonical_seals.load(Ordering::SeqCst),
            calls,
            "failure is sticky"
        );
        Canonical::preflight(ALGORITHMS[1], Policy::default()).unwrap();
        assert_eq!(module.canonical_seals.load(Ordering::SeqCst), calls + 8);
        return;
    }
    if case == "validated" {
        assert_eq!(
            Canonical::preflight(ALGORITHMS[0], Policy::default()),
            Err(Error::ValidationOptInRequired)
        );
        assert_eq!(module.canonical_seals.load(Ordering::SeqCst), 0);
        let policy = Policy::explicitly_allow_declared_validated();
        Canonical::preflight(ALGORITHMS[0], policy).unwrap();
        assert_eq!(module.canonical_seals.load(Ordering::SeqCst), 8);
        let fixture = Fixture::new(200, ALGORITHMS[0], DIRECTIONS[0]);
        assert_eq!(
            fixture
                .window
                .canonical_replies(Policy::default())
                .unwrap_err(),
            Error::ValidationOptInRequired
        );
        let replies = fixture.window.canonical_replies(policy).unwrap();
        let request = fixture.request(0);
        assert_eq!(replies.reply(&request).unwrap().bytes().len(), 57);
        module.set_serviceable(
            module
                .capabilities()
                .without(CryptoCapability::IkeEncryption),
        );
        assert_eq!(replies.reply(&request).unwrap_err(), Error::Unavailable);
        return;
    }
    if case == "concurrency" {
        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| Canonical::preflight(ALGORITHMS[0], Policy::default()).unwrap());
            }
        });
        assert_eq!(module.canonical_seals.load(Ordering::SeqCst), 8);
        let fixture = Fixture::new(201, ALGORITHMS[0], DIRECTIONS[1]);
        let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
        let request = fixture.request(1);
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..16)
                .map(|_| scope.spawn(|| replies.reply(&request).unwrap().bytes().to_vec()))
                .collect();
            let results: Vec<_> = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect();
            assert!(results.iter().all(|result| result == &results[0]));
        });
        assert_eq!(module.canonical_seals.load(Ordering::SeqCst), 9);
        return;
    }
    if case.starts_with("mixed-") {
        canonical_mixed_nonce_monitor(&module, case == "mixed-after");
        return;
    }
    Canonical::preflight(ALGORITHMS[0], Policy::default()).unwrap();
    if case == "interruption" {
        let fixture = Fixture::new(204, ALGORITHMS[0], DIRECTIONS[0]);
        let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
        let request = fixture.request(2);
        module.canonical_fault.store(7, Ordering::SeqCst);
        module.canonical_failures.store(1, Ordering::SeqCst);
        let before = module.canonical_seals.load(Ordering::SeqCst);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(replies.reply(&request));
        }))
        .is_err());
        module.canonical_fault.store(0, Ordering::SeqCst);
        assert_eq!(replies.reply(&request).unwrap_err(), Error::Unavailable);
        drop(replies);
        assert_eq!(
            fixture
                .window
                .canonical_replies(Policy::default())
                .unwrap_err(),
            Error::Unavailable
        );
        assert_eq!(module.canonical_seals.load(Ordering::SeqCst), before + 1);
        return;
    }
    if case == "readiness" {
        let fixture = Fixture::new(202, ALGORITHMS[0], DIRECTIONS[0]);
        let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
        let request = fixture.request(1);
        let packet = replies.reply(&request).unwrap().bytes().to_vec();
        let seals = module.canonical_seals.load(Ordering::SeqCst);
        module.set_serviceable(
            module
                .capabilities()
                .without(CryptoCapability::IkeEncryption),
        );
        assert_eq!(replies.reply(&request).unwrap_err(), Error::Unavailable);
        assert_eq!(module.canonical_seals.load(Ordering::SeqCst), seals);
        module.set_serviceable(module.capabilities());
        assert_eq!(replies.reply(&request).unwrap().bytes(), packet);
        module.drift_validation.store(true, Ordering::SeqCst);
        assert_eq!(replies.reply(&request).unwrap_err(), Error::Unavailable);
        return;
    }
    if case == "recreation" {
        let fixture = Fixture::new(203, ALGORITHMS[0], DIRECTIONS[0]);
        let request = fixture.request(2);
        module.canonical_fault.store(1, Ordering::SeqCst);
        module.canonical_failures.store(10, Ordering::SeqCst);
        let before = module.canonical_seals.load(Ordering::SeqCst);
        for _ in 0..3 {
            let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
            assert_eq!(replies.reply(&request).unwrap_err(), Error::InvalidOutput);
        }
        let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
        assert_eq!(
            replies.reply(&request).unwrap_err(),
            Error::AttemptsExhausted
        );
        assert_eq!(module.canonical_seals.load(Ordering::SeqCst), before + 3);
        return;
    }
    assert_eq!(case, "faults");
    for fault in 1..=5 {
        for withheld in 0..=3 {
            let fixture = Fixture::new(
                300 + u64::from(fault) * 10 + withheld,
                ALGORITHMS[0],
                DIRECTIONS[0],
            );
            let replies = fixture.window.canonical_replies(Policy::default()).unwrap();
            let request = fixture.request(4);
            module.canonical_fault.store(fault, Ordering::SeqCst);
            module
                .canonical_failures
                .store(usize::try_from(withheld).unwrap(), Ordering::SeqCst);
            let before = module.canonical_seals.load(Ordering::SeqCst);
            for _ in 0..withheld {
                let error = replies.reply(&request).unwrap_err();
                assert!(matches!(error, Error::InvalidOutput | Error::Unavailable));
                assert_eq!(format!("{replies:?}"), "Ikev2CanonicalEmptyReplies { .. }");
                let diagnostic =
                    format!("{error:?} {error} {:?}", std::error::Error::source(&error));
                assert!(!diagnostic.contains(HOSTILE_PROVIDER_DIAGNOSTIC));
                assert!(!diagnostic.contains("ciphertext"));
                assert!(diagnostic.len() < 150);
            }
            if withheld == 3 {
                assert_eq!(
                    replies.reply(&request).unwrap_err(),
                    Error::AttemptsExhausted
                );
                assert_eq!(module.canonical_seals.load(Ordering::SeqCst), before + 3);
            } else {
                let packet = replies.reply(&request).unwrap().bytes().to_vec();
                assert_eq!(replies.reply(&request).unwrap().bytes(), packet);
                replies.retire(4).unwrap();
                assert_eq!(replies.reply(&request).unwrap_err(), Error::AlreadyReleased);
                assert_eq!(
                    module.canonical_seals.load(Ordering::SeqCst),
                    before + usize::try_from(withheld).unwrap() + 1
                );
            }
        }
    }
}

fn canonical_mixed_nonce_monitor(module: &CountingModule, after_restart: bool) {
    use bytes::Bytes;
    use canonical_fixtures::{delete, empty, Fixture, ALGORITHMS, DIRECTIONS};
    use opc_proto_ikev2::{
        canonical::Ikev2CanonicalPolicy,
        recovery::{
            Ikev2CommittedWindow as Window, Ikev2CommittedWindowDomain as Domain,
            Ikev2CommittedWindowRecord as Record, Ikev2SyncClock as Clock,
            Ikev2SyncDisposition as Disposition, Ikev2SyncInitiatorAction as Action,
            Ikev2SyncRecoveryPolicy, Ikev2SyncResponderRecord as SyncRecord,
        },
        Ikev2AesGcmIvAllocator as Allocator, Ikev2AesGcmIvPurpose as Purpose,
        Ikev2ExchangeKind as Exchange, Ikev2MessageIdSyncAgreement as Agreement,
        Ikev2MessageIdSyncMode as Mode, Ikev2MessageIdSyncRole as Role, Ikev2MessageIdSyncSa as Sa,
    };
    module.monitor_aead.store(true, Ordering::SeqCst);
    for algorithm in ALGORITHMS {
        for epoch in 0..2 {
            for direction in DIRECTIONS {
                let profile = canonical_fixtures::profile(algorithm);
                let keys = canonical_fixtures::key_material(profile, 400 + epoch);
                // The rekey epoch also exercises equal AES keys with distinct
                // directional salts; aggregate usage includes both nonce domains.
                let keys = if epoch == 1 {
                    let mut er = keys.sk_ei().to_vec();
                    let key_len = er.len() - 4;
                    er[key_len..].copy_from_slice(&keys.sk_er()[key_len..]);
                    opc_proto_ikev2::Ikev2SaInitKeyMaterial::from_established_keys(
                        profile,
                        false,
                        keys.sk_d(),
                        &[],
                        &[],
                        keys.sk_ei(),
                        &er,
                        keys.sk_pi(),
                        keys.sk_pr(),
                    )
                    .unwrap()
                } else {
                    keys
                };
                let spis = (
                    canonical_fixtures::SPIS.0 + epoch,
                    canonical_fixtures::SPIS.1 + epoch,
                );
                let mut fixture = if after_restart {
                    Fixture::from_persisted_keys(profile, keys, direction, spis, 64)
                } else {
                    Fixture::from_keys(profile, keys, direction, spis)
                };
                if after_restart {
                    // Restore the persisted IV end, discarding the old unused tail.
                    // Replaying an old same-binding window snapshot deliberately
                    // checks that canonical nonce safety does not depend on floors.
                    fixture.allocator =
                        Allocator::restore(fixture.iv.domain(), &fixture.iv).unwrap();
                    let prepared = fixture.allocator.prepare(64, Purpose::Ordinary).unwrap();
                    fixture.iv = prepared.record().clone();
                    prepared.activate_after_commit(&fixture.iv).unwrap();
                    fixture.window = fixture.restore(&fixture.iv);
                }
                let domain = Domain::from_iv_record(&fixture.iv);
                let role = if direction == DIRECTIONS[0] {
                    Role::Initiator
                } else {
                    Role::Responder
                };
                let agreement = Agreement::from_persisted(
                    Sa::new(fixture.spis.0, fixture.spis.1, role).unwrap(),
                    Mode::Negotiated,
                );
                let record = Record::initial(domain.clone(), 0, 0)
                    .with_sync_state(
                        SyncRecord::from_persisted(
                            agreement,
                            None,
                            None,
                            None,
                            None,
                            Disposition::Continue,
                            0,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                fixture.window = Window::restore(
                    &domain,
                    fixture.profile,
                    &fixture.keys,
                    &record,
                    &fixture.iv,
                )
                .unwrap();
                let replies = fixture
                    .window
                    .canonical_replies(Ikev2CanonicalPolicy::default())
                    .unwrap();
                let empty_request = fixture.request(9);
                let before = module.counts.entropy.load(Ordering::SeqCst);
                let first = replies.reply(&empty_request).unwrap().bytes().to_vec();
                assert_eq!(replies.reply(&empty_request).unwrap().bytes(), first);
                assert_eq!(module.counts.entropy.load(Ordering::SeqCst), before);

                let prepared = fixture
                    .window
                    .prepare_request(
                        fixture.profile,
                        &fixture.keys,
                        fixture.allocator.allocate(Purpose::Ordinary).unwrap(),
                        Exchange::Informational,
                        delete(),
                    )
                    .unwrap();
                let committed = prepared.record().clone();
                let _receipt = prepared.commit_after_durable(&committed).unwrap();
                let peer_request = fixture.peer(0, false, 37, delete(), 0, 0x2000);
                let request = fixture
                    .window
                    .open_peer(fixture.profile, &fixture.keys, &peer_request)
                    .unwrap();
                let prepared = fixture
                    .window
                    .prepare_response(
                        fixture.profile,
                        &fixture.keys,
                        fixture.allocator.allocate(Purpose::Ordinary).unwrap(),
                        &request,
                        empty(),
                        Bytes::new(),
                    )
                    .unwrap();
                let committed = prepared.record().clone();
                let _receipt = prepared.commit_after_durable(&committed).unwrap();
                let peer_response = fixture.peer(0, true, 37, empty(), 0, 0x2001);
                let response = fixture
                    .window
                    .open_peer(fixture.profile, &fixture.keys, &peer_response)
                    .unwrap();
                let prepared = fixture
                    .window
                    .prepare_completion(&response, Bytes::new())
                    .unwrap();
                let committed = prepared.record().clone();
                let _receipt = prepared.commit_after_durable(&committed).unwrap();
                let sync = [
                    0, 0, 0, 20, 0, 0, 0x40, 0x26, 1, 2, 3, 4, 0, 0, 0, 10, 0, 0, 0, 10,
                ];
                let wire = fixture.peer(
                    0,
                    false,
                    37,
                    opc_proto_ikev2::PayloadChain::new(PayloadType::Notify, &sync),
                    0,
                    0x2002,
                );
                let admitted = fixture
                    .window
                    .begin_sync_response(fixture.profile, &fixture.keys, &wire, None, None)
                    .unwrap();
                let prepared = admitted
                    .prepare(
                        fixture.profile,
                        &fixture.keys,
                        fixture.allocator.allocate(Purpose::Ordinary).unwrap(),
                    )
                    .unwrap();
                let committed = prepared.record().clone();
                let receipt = prepared.commit_after_durable(&committed).unwrap();
                let _response = fixture.window.release_sync_response(receipt).unwrap();

                let now = Clock::new(100, 1);
                let policy = Ikev2SyncRecoveryPolicy::new(1, now, 200, 3, 10).unwrap();
                module.sync_entropy_mode.store(1, Ordering::SeqCst);
                let prepared = fixture
                    .window
                    .begin_sync(policy, now, None)
                    .unwrap()
                    .prepare(
                        fixture.profile,
                        &fixture.keys,
                        fixture.allocator.allocate(Purpose::Ordinary).unwrap(),
                    )
                    .unwrap();
                let committed = prepared.record().clone();
                let receipt = prepared.commit_after_durable(&committed, now).unwrap();
                assert!(matches!(
                    fixture.window.release_sync_action(receipt, now).unwrap(),
                    Action::SendRequest(_)
                ));
                assert_eq!(
                    fixture
                        .window
                        .canonical_replies(Ikev2CanonicalPolicy::default())
                        .unwrap_err(),
                    opc_proto_ikev2::canonical::Ikev2CanonicalError::LifecycleBlocked
                );
                // A Child-SA rekey does not reset the IKE domain; the same
                // pre-existing canonical recipe still yields the same bytes.
                // Sending/admission is intentionally not granted by this primitive.
                assert_eq!(replies.reply(&empty_request).unwrap().bytes(), first);
            }
        }
    }
    let observed = module.observed_aead.lock().unwrap();
    let encode = |value: &[u8]| {
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let trace: String = observed
        .iter()
        .map(|value| {
            format!(
                "{} {}:{}\n",
                encode(&value.key_nonce),
                encode(&value.aad),
                encode(&value.plaintext)
            )
        })
        .collect();
    std::fs::write(
        std::env::var("OPC_CANONICAL_TRANSCRIPT_PATH").unwrap(),
        trace,
    )
    .unwrap();
    assert!(observed.len() > 100);
}
