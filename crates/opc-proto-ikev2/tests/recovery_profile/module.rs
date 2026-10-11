//! Transparent provider instrumentation; every primitive delegates to SDK software.
//! Counters are thread-local so unrelated parallel tests cannot change an oracle.

use opc_crypto_provider::{
    CapabilitySet, CryptoCapability, CryptoModule, CryptoOperationError, IkeAeadAlgorithm,
    IkeCbcAlgorithm, IkeDhGroup, IkeDhKeyPair, IkeDiffieHellmanOperations, IkeEncryptionOperations,
    IkeEntropyOperations, IkeHashAlgorithm, IkeHashOperations, IkeIntegrityAlgorithm,
    IkeIntegrityOperations, IkePrfAlgorithm, IkePrfOperations, IkeSignatureAlgorithm,
    IkeSignatureOperations, IkeSigningKey, ModuleReadiness, ProviderIdentity, ProviderPolicy,
    SelfTestError, SelfTestOutcome, ValidationState,
};
use opc_proto_ikev2::{
    install_ikev2_crypto_module, Ikev2CryptoRequirements, Ikev2DhGroup, Ikev2SoftwareCryptoModule,
    Ikev2SoftwareCryptoOperations,
};
use std::{
    cell::Cell,
    future::Future,
    pin::pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll, Waker},
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub entropy: u64,
    pub dh_generate: u64,
    pub dh_import: u64,
    pub seal_aead: u64,
    pub encrypt_cbc: u64,
}
thread_local! { static COUNTS: Cell<Counts> = const { Cell::new(Counts {
entropy: 0, dh_generate: 0, dh_import: 0, seal_aead: 0, encrypt_cbc: 0 }) }; }
fn count(update: impl FnOnce(&mut Counts)) {
    COUNTS.with(|cell| {
        let mut counts = cell.get();
        update(&mut counts);
        cell.set(counts);
    });
}
pub fn counts() -> Counts {
    COUNTS.with(Cell::get)
}

thread_local! { static BAD_OUTPUT: Cell<bool> = const { Cell::new(false) }; }
pub fn bad_output<T>(action: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            BAD_OUTPUT.with(|fault| fault.set(self.0));
        }
    }
    let _reset = Reset(BAD_OUTPUT.with(|fault| fault.replace(true)));
    action()
}
fn output(result: Result<Vec<u8>, CryptoOperationError>) -> Result<Vec<u8>, CryptoOperationError> {
    let mut bytes = result?;
    if BAD_OUTPUT.with(Cell::get) {
        if let Some(last) = bytes.last_mut() {
            *last ^= 1;
        }
    }
    Ok(bytes)
}

thread_local! { static CHECKPOINT_FAULT: Cell<Option<opc_crypto_provider::CryptoOperationErrorCode>> = const { Cell::new(None) }; }
pub fn checkpoint_fault<T>(
    code: opc_crypto_provider::CryptoOperationErrorCode,
    action: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<opc_crypto_provider::CryptoOperationErrorCode>);
    impl Drop for Reset {
        fn drop(&mut self) {
            CHECKPOINT_FAULT.with(|fault| fault.set(self.0));
        }
    }
    let _reset = Reset(CHECKPOINT_FAULT.with(|fault| fault.replace(Some(code))));
    action()
}
fn checkpoint_available() -> Result<(), CryptoOperationError> {
    if let Some(code) = CHECKPOINT_FAULT.with(Cell::get) {
        return Err(CryptoOperationError::new(code));
    }
    Ok(())
}

thread_local! { static WITHDRAWN: Cell<Option<CryptoCapability>> = const { Cell::new(None) }; }
pub fn withdraw<T>(capability: CryptoCapability, action: impl FnOnce() -> T) -> T {
    struct Reset(Option<CryptoCapability>);
    impl Drop for Reset {
        fn drop(&mut self) {
            WITHDRAWN.with(|fault| fault.set(self.0));
        }
    }
    let _reset = Reset(WITHDRAWN.with(|fault| fault.replace(Some(capability))));
    action()
}
struct CheckpointHandle(Box<dyn IkeDhKeyPair>);
impl std::fmt::Debug for CheckpointHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointHandle").finish_non_exhaustive()
    }
}
impl IkeDhKeyPair for CheckpointHandle {
    fn group(&self) -> IkeDhGroup {
        self.0.group()
    }
    fn public_value(&self) -> &[u8] {
        if BAD_OUTPUT.with(Cell::get) {
            &[]
        } else {
            self.0.public_value()
        }
    }
    fn agree(&self, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        self.0.agree(peer)
    }
    fn export_private_checkpoint(&mut self) -> Result<Zeroizing<Vec<u8>>, CryptoOperationError> {
        checkpoint_available()?;
        self.0.export_private_checkpoint()
    }
}

pub fn ready<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    match pin!(future).poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the deterministic provider unexpectedly waited"),
    }
}

pub fn install() {
    static INSTALL: OnceLock<()> = OnceLock::new();
    INSTALL.get_or_init(|| {
        let mut requirements = Ikev2CryptoRequirements::all_software_supported();
        for group in [
            Ikev2DhGroup::Modp768,
            Ikev2DhGroup::Modp1024,
            Ikev2DhGroup::Modp2048,
            Ikev2DhGroup::Ecp256,
            Ikev2DhGroup::Ecp384,
            Ikev2DhGroup::Ecp521,
        ] {
            requirements.require_dh_checkpoint(group);
        }
        let policy = ProviderPolicy::new().require_all(requirements.required_capabilities());
        let build = std::env::var("OPC_RECOVERY_MODULE_BUILD").unwrap_or_else(|_| "1".into());
        let module = InstrumentedModule {
            identity: ProviderIdentity::from_parts("recovery-profile-fixture", &build).unwrap(),
            inner: Ikev2SoftwareCryptoModule::new().unwrap(),
            operations: Ikev2SoftwareCryptoOperations::new(),
        };
        let _report = ready(install_ikev2_crypto_module(
            Arc::new(module),
            policy,
            requirements,
        ))
        .unwrap();
    });
}

struct InstrumentedModule {
    identity: ProviderIdentity,
    inner: Ikev2SoftwareCryptoModule,
    operations: Ikev2SoftwareCryptoOperations,
}

#[async_trait::async_trait]
impl CryptoModule for InstrumentedModule {
    fn identity(&self) -> ProviderIdentity {
        self.identity.clone()
    }

    fn validation_state(&self) -> ValidationState {
        self.inner.validation_state()
    }

    fn advertised_capabilities(&self) -> CapabilitySet {
        self.inner.advertised_capabilities()
    }

    async fn self_test(&self) -> Result<SelfTestOutcome, SelfTestError> {
        self.inner.self_test().await
    }

    fn readiness(&self) -> ModuleReadiness {
        let readiness = self.inner.readiness();
        WITHDRAWN.with(Cell::get).map_or(readiness, |capability| {
            ModuleReadiness::serviceable(readiness.serviceable_capabilities().without(capability))
        })
    }
}

impl IkeHashOperations for InstrumentedModule {
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

impl IkeEntropyOperations for InstrumentedModule {
    fn fill_random(&self, output: &mut [u8]) -> Result<(), CryptoOperationError> {
        count(|c| c.entropy += 1);
        self.operations.fill_random(output)
    }
}

impl IkePrfOperations for InstrumentedModule {
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

impl IkeIntegrityOperations for InstrumentedModule {
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

impl IkeEncryptionOperations for InstrumentedModule {
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
        count(|c| c.seal_aead += 1);
        output(self.operations.seal_aead(
            algorithm,
            key,
            salt,
            explicit_iv,
            associated_data,
            plaintext,
        ))
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
        count(|c| c.encrypt_cbc += 1);
        output(self.operations.encrypt_cbc(algorithm, key, iv, plaintext))
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

impl IkeDiffieHellmanOperations for InstrumentedModule {
    fn supports_dh_checkpoint(&self, group: IkeDhGroup) -> bool {
        self.operations.supports_dh_checkpoint(group)
    }

    fn import_keypair_checkpoint(
        &self,
        group: IkeDhGroup,
        checkpoint: &[u8],
        expected_public_value: &[u8],
    ) -> Result<Box<dyn IkeDhKeyPair>, CryptoOperationError> {
        count(|c| c.dh_import += 1);
        checkpoint_available()?;
        self.operations
            .import_keypair_checkpoint(group, checkpoint, expected_public_value)
            .map(|key| Box::new(CheckpointHandle(key)) as Box<dyn IkeDhKeyPair>)
    }

    fn supports_dh_group(&self, group: IkeDhGroup) -> bool {
        self.operations.supports_dh_group(group)
    }

    fn generate_keypair(
        &self,
        group: IkeDhGroup,
    ) -> Result<Box<dyn IkeDhKeyPair>, CryptoOperationError> {
        count(|c| c.dh_generate += 1);
        self.operations
            .generate_keypair(group)
            .map(|key| Box::new(CheckpointHandle(key)) as Box<dyn IkeDhKeyPair>)
    }
}

impl IkeSignatureOperations for InstrumentedModule {
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
