use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex, OnceLock,
};

use async_trait::async_trait;
use opc_crypto_provider::{
    probe_capability_report, CapabilityReport, CapabilitySet, CryptoCapability, CryptoModule,
    ModuleReadiness, PolicyError, ProviderIdentity, ProviderPolicy, SelfTestError, SelfTestOutcome,
    ValidationState,
};
use opc_types::TenantId;
use zeroize::Zeroizing;

use super::{
    admitted_key_custody, install_key_custody_module, install_key_custody_module_with_report,
    key_custody_required_capabilities, seal_with_slot, unseal_with_slot, KeyCustodyInstallError,
    MAX_KEY_CUSTODY_BOUND_AAD_BYTES,
};
use crate::{
    key_id_from_bound_aad, serialize_bound_aad, EncryptedPayload, EnvelopeAad, KeyCustodyModule,
    KeyCustodyOperationError, KeyError, KeyId, RemoteSealProvider, SessionAad,
};

const KEY_MATERIAL_CANARY: &str = "provider-owned-key-material-canary";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderMode {
    Valid,
    OversizedAad,
    MalformedAad,
    NonCanonicalAad,
    MismatchedAad,
    NotFound,
    Unavailable,
    SensitiveError,
}

struct CountingCustodyModule {
    identity: Mutex<ProviderIdentity>,
    validation: Mutex<ValidationState>,
    advertised: Mutex<CapabilitySet>,
    serviceable: Mutex<CapabilitySet>,
    self_test_passed: Mutex<CapabilitySet>,
    self_test_unavailable: Mutex<bool>,
    mode: Mutex<ProviderMode>,
    key_id: KeyId,
    _provider_owned_key: Zeroizing<Vec<u8>>,
    self_test_calls: AtomicUsize,
    seal_calls: AtomicUsize,
    unseal_calls: AtomicUsize,
}

impl std::fmt::Debug for CountingCustodyModule {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CountingCustodyModule")
            .field(
                "self_test_calls",
                &self.self_test_calls.load(Ordering::SeqCst),
            )
            .field("seal_calls", &self.seal_calls.load(Ordering::SeqCst))
            .field("unseal_calls", &self.unseal_calls.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl CountingCustodyModule {
    fn new(capabilities: CapabilitySet) -> Self {
        Self {
            identity: Mutex::new(
                ProviderIdentity::from_parts("custody test module", "1.0")
                    .expect("bounded identity"),
            ),
            validation: Mutex::new(ValidationState::NotValidated),
            advertised: Mutex::new(capabilities),
            serviceable: Mutex::new(capabilities),
            self_test_passed: Mutex::new(capabilities),
            self_test_unavailable: Mutex::new(false),
            mode: Mutex::new(ProviderMode::Valid),
            key_id: KeyId::new("provider-owned-session-key").expect("key id"),
            _provider_owned_key: Zeroizing::new(KEY_MATERIAL_CANARY.as_bytes().to_vec()),
            self_test_calls: AtomicUsize::new(0),
            seal_calls: AtomicUsize::new(0),
            unseal_calls: AtomicUsize::new(0),
        }
    }

    fn set_identity(&self, name: &str) {
        *self.identity.lock().expect("identity lock") =
            ProviderIdentity::from_parts(name, "1.0").expect("bounded identity");
    }

    fn set_validation(&self, validation: ValidationState) {
        *self.validation.lock().expect("validation lock") = validation;
    }

    fn set_advertised(&self, capabilities: CapabilitySet) {
        *self.advertised.lock().expect("advertised lock") = capabilities;
    }

    fn set_serviceable(&self, capabilities: CapabilitySet) {
        *self.serviceable.lock().expect("serviceable lock") = capabilities;
    }

    fn set_self_test_passed(&self, capabilities: CapabilitySet) {
        *self
            .self_test_passed
            .lock()
            .expect("self-test outcome lock") = capabilities;
    }

    fn set_self_test_unavailable(&self, unavailable: bool) {
        *self
            .self_test_unavailable
            .lock()
            .expect("self-test availability lock") = unavailable;
    }

    fn set_mode(&self, mode: ProviderMode) {
        *self.mode.lock().expect("provider mode lock") = mode;
    }

    fn valid_payload(&self, aad: &EnvelopeAad) -> EncryptedPayload {
        EncryptedPayload {
            aad: serialize_bound_aad(aad, &self.key_id).expect("test AAD"),
            ciphertext_and_tag: b"provider-ciphertext".to_vec(),
        }
    }
}

#[async_trait]
impl CryptoModule for CountingCustodyModule {
    fn identity(&self) -> ProviderIdentity {
        self.identity.lock().expect("identity lock").clone()
    }

    fn validation_state(&self) -> ValidationState {
        self.validation.lock().expect("validation lock").clone()
    }

    fn advertised_capabilities(&self) -> CapabilitySet {
        *self.advertised.lock().expect("advertised lock")
    }

    async fn self_test(&self) -> Result<SelfTestOutcome, SelfTestError> {
        self.self_test_calls.fetch_add(1, Ordering::SeqCst);
        if *self
            .self_test_unavailable
            .lock()
            .expect("self-test availability lock")
        {
            return Err(SelfTestError::ModuleUnavailable);
        }
        Ok(SelfTestOutcome::new(
            *self
                .self_test_passed
                .lock()
                .expect("self-test outcome lock"),
            CapabilitySet::empty(),
        ))
    }

    fn readiness(&self) -> ModuleReadiness {
        ModuleReadiness::serviceable(*self.serviceable.lock().expect("serviceable lock"))
    }
}

#[async_trait]
impl RemoteSealProvider for CountingCustodyModule {
    async fn seal(
        &self,
        aad: &EnvelopeAad,
        _plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        self.seal_calls.fetch_add(1, Ordering::SeqCst);
        match *self.mode.lock().expect("provider mode lock") {
            ProviderMode::Valid => Ok(self.valid_payload(aad)),
            ProviderMode::OversizedAad => Ok(EncryptedPayload {
                aad: vec![b'x'; MAX_KEY_CUSTODY_BOUND_AAD_BYTES + 1],
                ciphertext_and_tag: b"provider-ciphertext".to_vec(),
            }),
            ProviderMode::MalformedAad => Ok(EncryptedPayload {
                aad: b"{malformed".to_vec(),
                ciphertext_and_tag: b"provider-ciphertext".to_vec(),
            }),
            ProviderMode::NonCanonicalAad => {
                let mut payload = self.valid_payload(aad);
                payload.aad.insert(0, b' ');
                Ok(payload)
            }
            ProviderMode::MismatchedAad => {
                let other_aad = EnvelopeAad::session(
                    TenantId::new("other-tenant").expect("other tenant"),
                    1,
                    SessionAad::new("smf", "other-session", "state", 1, 1, "store")
                        .expect("other AAD"),
                );
                Ok(self.valid_payload(&other_aad))
            }
            ProviderMode::NotFound => Err(KeyError::NotFound),
            ProviderMode::Unavailable => Err(KeyError::Unavailable),
            ProviderMode::SensitiveError => Err(KeyError::InvalidMetadata {
                field: "provider",
                message: KEY_MATERIAL_CANARY.to_string(),
            }),
        }
    }

    async fn unseal(
        &self,
        _key_id: &KeyId,
        _aad: &EnvelopeAad,
        _ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        self.unseal_calls.fetch_add(1, Ordering::SeqCst);
        match *self.mode.lock().expect("provider mode lock") {
            ProviderMode::NotFound => Err(KeyError::NotFound),
            ProviderMode::Unavailable => Err(KeyError::Unavailable),
            ProviderMode::SensitiveError => Err(KeyError::InvalidMetadata {
                field: "provider",
                message: KEY_MATERIAL_CANARY.to_string(),
            }),
            ProviderMode::Valid
            | ProviderMode::OversizedAad
            | ProviderMode::MalformedAad
            | ProviderMode::NonCanonicalAad
            | ProviderMode::MismatchedAad => Ok(Zeroizing::new(b"provider-plaintext".to_vec())),
        }
    }
}

fn required_policy() -> ProviderPolicy {
    ProviderPolicy::new()
        .require(CryptoCapability::SealedKeyStorage)
        .require(CryptoCapability::Zeroization)
}

fn session_aad() -> EnvelopeAad {
    EnvelopeAad::session(
        TenantId::new("tenant-a").expect("tenant"),
        1,
        SessionAad::new("smf", "session-digest", "state", 1, 1, "store").expect("session AAD"),
    )
}

async fn report(module: &Arc<CountingCustodyModule>) -> CapabilityReport {
    probe_capability_report(module.as_ref()).await
}

fn as_module(module: &Arc<CountingCustodyModule>) -> Arc<dyn KeyCustodyModule> {
    module.clone()
}

fn assert_custody_error(error: KeyError, expected: KeyCustodyOperationError) {
    assert_eq!(error, KeyError::CustodyOperation(expected));
    assert_eq!(error.to_string(), expected.as_str());
    assert!(!format!("{error:?} {error}").contains(KEY_MATERIAL_CANARY));
}

#[test]
fn required_capabilities_and_error_codes_are_stable() {
    let required = key_custody_required_capabilities();
    assert_eq!(required.len(), 2);
    assert!(required.contains(CryptoCapability::SealedKeyStorage));
    assert!(required.contains(CryptoCapability::Zeroization));

    let cases = [
        (
            KeyCustodyOperationError::NotInstalled,
            "key_custody_not_installed",
        ),
        (
            KeyCustodyOperationError::IdentityChanged,
            "key_custody_identity_changed",
        ),
        (
            KeyCustodyOperationError::ValidationChanged,
            "key_custody_validation_changed",
        ),
        (
            KeyCustodyOperationError::CapabilityNotAdmitted,
            "key_custody_capability_not_admitted",
        ),
        (
            KeyCustodyOperationError::CapabilityWithdrawn,
            "key_custody_capability_withdrawn",
        ),
        (
            KeyCustodyOperationError::ProviderOperationFailed,
            "key_custody_provider_operation_failed",
        ),
        (
            KeyCustodyOperationError::InvalidProviderOutput,
            "key_custody_invalid_provider_output",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.as_str(), code);
        assert_eq!(error.to_string(), code);
        assert_eq!(KeyError::from(error).to_string(), code);
    }
}

#[tokio::test]
async fn admission_failures_leave_a_local_slot_empty() {
    let required = key_custody_required_capabilities();

    let missing_policy_module = Arc::new(CountingCustodyModule::new(required));
    let missing_policy_report = report(&missing_policy_module).await;
    let missing_policy_slot = OnceLock::new();
    let error = install_key_custody_module_with_report(
        &missing_policy_slot,
        as_module(&missing_policy_module),
        ProviderPolicy::new().require(CryptoCapability::SealedKeyStorage),
        missing_policy_report,
    )
    .expect_err("zeroization must be explicit");
    assert_eq!(
        error,
        KeyCustodyInstallError::PolicyMissingCapabilities {
            missing: CapabilitySet::empty().with(CryptoCapability::Zeroization),
        }
    );
    assert!(missing_policy_slot.get().is_none());

    let failed_self_test_module = Arc::new(CountingCustodyModule::new(required));
    failed_self_test_module.set_self_test_passed(CapabilitySet::empty());
    let failed_report = report(&failed_self_test_module).await;
    let failed_slot = OnceLock::new();
    assert!(matches!(
        install_key_custody_module_with_report(
            &failed_slot,
            as_module(&failed_self_test_module),
            required_policy(),
            failed_report,
        ),
        Err(KeyCustodyInstallError::PolicyRejected(
            PolicyError::CapabilityUnavailable { .. }
        ))
    ));
    assert!(failed_slot.get().is_none());

    let unavailable_self_test_module = Arc::new(CountingCustodyModule::new(required));
    unavailable_self_test_module.set_self_test_unavailable(true);
    let unavailable_report = report(&unavailable_self_test_module).await;
    let unavailable_slot = OnceLock::new();
    assert!(matches!(
        install_key_custody_module_with_report(
            &unavailable_slot,
            as_module(&unavailable_self_test_module),
            required_policy(),
            unavailable_report,
        ),
        Err(KeyCustodyInstallError::PolicyRejected(
            PolicyError::CapabilityUnavailable { .. }
        ))
    ));
    assert!(unavailable_slot.get().is_none());

    let changed_module = Arc::new(CountingCustodyModule::new(required));
    let stale_report = report(&changed_module).await;
    changed_module.set_identity("replacement custody module");
    let changed_slot = OnceLock::new();
    assert_eq!(
        install_key_custody_module_with_report(
            &changed_slot,
            as_module(&changed_module),
            required_policy(),
            stale_report,
        ),
        Err(KeyCustodyInstallError::EvidenceChanged)
    );
    assert!(changed_slot.get().is_none());
    assert_eq!(changed_module.seal_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn live_checks_cover_the_complete_granted_set_before_dispatch() {
    let granted = key_custody_required_capabilities().with(CryptoCapability::ApprovedEntropy);
    let policy = required_policy().require(CryptoCapability::ApprovedEntropy);
    let module = Arc::new(CountingCustodyModule::new(granted));
    let admitted_report = report(&module).await;
    assert_eq!(
        module.self_test_calls.load(Ordering::SeqCst),
        1,
        "admission must run the module self-test exactly once"
    );
    let slot = OnceLock::new();
    assert_eq!(
        install_key_custody_module_with_report(
            &slot,
            as_module(&module),
            policy,
            admitted_report.clone(),
        )
        .expect("install"),
        admitted_report
    );
    assert_eq!(
        slot.get().expect("installed").report,
        admitted_report,
        "the exact report returned to the caller must stay in the slot"
    );

    let aad = session_aad();
    let valid = seal_with_slot(&slot, &aad, b"plaintext")
        .await
        .expect("admitted seal");
    assert_eq!(
        key_id_from_bound_aad(&valid.aad).expect("returned key id"),
        module.key_id
    );
    assert_eq!(
        valid.ciphertext_and_tag, b"provider-ciphertext",
        "the admitted object must supply the exact provider result"
    );
    assert_eq!(module.seal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        unseal_with_slot(&slot, &module.key_id, &aad, &valid.ciphertext_and_tag)
            .await
            .expect("admitted unseal")
            .as_slice(),
        b"provider-plaintext"
    );
    assert_eq!(module.unseal_calls.load(Ordering::SeqCst), 1);

    module.set_serviceable(granted.without(CryptoCapability::ApprovedEntropy));
    assert_custody_error(
        seal_with_slot(&slot, &aad, b"blocked")
            .await
            .expect_err("withdrawn non-custody grant must block coherently"),
        KeyCustodyOperationError::CapabilityWithdrawn,
    );
    assert_eq!(module.seal_calls.load(Ordering::SeqCst), 1);
    assert_custody_error(
        unseal_with_slot(&slot, &module.key_id, &aad, b"blocked")
            .await
            .expect_err("withdrawn extra grant must also block unseal"),
        KeyCustodyOperationError::CapabilityWithdrawn,
    );
    assert_eq!(module.unseal_calls.load(Ordering::SeqCst), 1);

    module.set_serviceable(granted);
    module.set_advertised(granted.without(CryptoCapability::Zeroization));
    assert_custody_error(
        seal_with_slot(&slot, &aad, b"blocked")
            .await
            .expect_err("withdrawn custody grant must block"),
        KeyCustodyOperationError::CapabilityWithdrawn,
    );
    assert_eq!(module.seal_calls.load(Ordering::SeqCst), 1);

    module.set_advertised(granted);
    module.set_identity("changed custody module");
    assert_custody_error(
        seal_with_slot(&slot, &aad, b"blocked")
            .await
            .expect_err("identity mutation must block"),
        KeyCustodyOperationError::IdentityChanged,
    );
    assert_eq!(module.seal_calls.load(Ordering::SeqCst), 1);

    module.set_identity("custody test module");
    module.set_validation(ValidationState::DeclaredValidated { reference: None });
    assert_custody_error(
        seal_with_slot(&slot, &aad, b"blocked")
            .await
            .expect_err("validation mutation must block"),
        KeyCustodyOperationError::ValidationChanged,
    );
    assert_eq!(module.seal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(module.unseal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        module.self_test_calls.load(Ordering::SeqCst),
        1,
        "operations and live withdrawal checks must not rerun self-test"
    );
}

#[tokio::test]
async fn provider_outputs_are_bounded_canonical_and_context_exact() {
    let required = key_custody_required_capabilities();
    let module = Arc::new(CountingCustodyModule::new(required));
    let slot = OnceLock::new();
    let _admitted_report = install_key_custody_module_with_report(
        &slot,
        as_module(&module),
        required_policy(),
        report(&module).await,
    )
    .expect("install");
    let aad = session_aad();

    for mode in [
        ProviderMode::OversizedAad,
        ProviderMode::MalformedAad,
        ProviderMode::NonCanonicalAad,
        ProviderMode::MismatchedAad,
    ] {
        module.set_mode(mode);
        assert_custody_error(
            seal_with_slot(&slot, &aad, b"plaintext")
                .await
                .expect_err("malfunctioning output must fail closed"),
            KeyCustodyOperationError::InvalidProviderOutput,
        );
    }
    assert_eq!(module.seal_calls.load(Ordering::SeqCst), 4);
    assert_eq!(module.self_test_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn provider_errors_preserve_only_safe_public_classifications() {
    let required = key_custody_required_capabilities();
    let module = Arc::new(CountingCustodyModule::new(required));
    let slot = OnceLock::new();
    let _admitted_report = install_key_custody_module_with_report(
        &slot,
        as_module(&module),
        required_policy(),
        report(&module).await,
    )
    .expect("install");
    let aad = session_aad();

    module.set_mode(ProviderMode::NotFound);
    assert_eq!(
        unseal_with_slot(&slot, &module.key_id, &aad, b"ciphertext")
            .await
            .expect_err("not found"),
        KeyError::NotFound
    );

    module.set_mode(ProviderMode::Unavailable);
    assert_eq!(
        unseal_with_slot(&slot, &module.key_id, &aad, b"ciphertext")
            .await
            .expect_err("unavailable"),
        KeyError::Unavailable
    );

    module.set_mode(ProviderMode::SensitiveError);
    let error = unseal_with_slot(&slot, &module.key_id, &aad, b"ciphertext")
        .await
        .expect_err("contextual provider errors must collapse");
    assert_custody_error(error, KeyCustodyOperationError::ProviderOperationFailed);

    module.set_mode(ProviderMode::Valid);
    assert_eq!(
        unseal_with_slot(&slot, &module.key_id, &aad, b"ciphertext")
            .await
            .expect("valid unseal")
            .as_slice(),
        b"provider-plaintext"
    );
    assert_eq!(
        module.self_test_calls.load(Ordering::SeqCst),
        1,
        "provider outcomes must not rerun the admission-time self-test"
    );
}

#[tokio::test]
async fn process_install_returns_evidence_and_exposes_only_the_opaque_handle() {
    let required = key_custody_required_capabilities();
    let module = Arc::new(CountingCustodyModule::new(required));

    assert_eq!(
        admitted_key_custody().expect_err("slot starts empty"),
        KeyCustodyOperationError::NotInstalled
    );

    let admitted_report = install_key_custody_module(as_module(&module), required_policy())
        .await
        .expect("process install");
    let handle = admitted_key_custody().expect("opaque admitted handle");
    assert_eq!(
        handle.admission_report().expect("admission report"),
        admitted_report
    );

    let aad = session_aad();
    let payload = handle
        .seal(&aad, b"plaintext")
        .await
        .expect("process-routed seal");
    assert_eq!(payload.ciphertext_and_tag, b"provider-ciphertext");
    assert_eq!(
        handle
            .unseal(&module.key_id, &aad, payload.ciphertext_and_tag.as_slice())
            .await
            .expect("process-routed unseal")
            .as_slice(),
        b"provider-plaintext"
    );
    assert_eq!(module.seal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(module.unseal_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        module.self_test_calls.load(Ordering::SeqCst),
        1,
        "successful operations must retain admission-time self-test evidence"
    );

    let duplicate = Arc::new(CountingCustodyModule::new(required));
    assert_eq!(
        install_key_custody_module(as_module(&duplicate), required_policy())
            .await
            .expect_err("process slot must be immutable"),
        KeyCustodyInstallError::AlreadyInstalled
    );
    assert_eq!(
        duplicate.self_test_calls.load(Ordering::SeqCst),
        0,
        "duplicate install must not probe an unselected module"
    );

    let rendered = format!(
        "{handle:?} {admitted_report:?} {module:?} {}",
        KeyCustodyOperationError::ProviderOperationFailed
    );
    assert!(!rendered.contains(KEY_MATERIAL_CANARY));
    assert!(!rendered.contains(module.key_id.as_str()));
    assert!(!rendered.contains("tenant-a"));
}
