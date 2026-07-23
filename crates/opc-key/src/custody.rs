//! Process-level admission and routing for provider-owned sealed key custody.
//!
//! The selected module is installed exactly once after its capability evidence
//! satisfies an explicit [`ProviderPolicy`]. The installed object supplies both
//! [`CryptoModule`] evidence and [`RemoteSealProvider`] operations, so evidence
//! from one provider cannot authorize sealing through another. There is no
//! implicit local or remote fallback inside [`AdmittedKeyCustody`].

use std::{
    error::Error,
    fmt,
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use opc_crypto_provider::{
    probe_capability_report, CapabilityReport, CapabilitySet, CryptoCapability, CryptoModule,
    PolicyAdmission, PolicyError, ProviderPolicy,
};
use zeroize::Zeroizing;

use crate::{
    decode_bound_aad,
    errors::{KeyCustodyOperationError, KeyError},
    remote::RemoteSealProvider,
    scope::{serialize_bound_aad, EnvelopeAad, KeyId},
    EncryptedPayload,
};

/// Maximum bound-AAD bytes accepted from a successful admitted provider.
///
/// The cap is applied before JSON parsing or canonicalization. It bounds work
/// performed on a malfunctioning provider response while leaving ample room
/// for the SDK's structured persistence metadata. Inputs whose canonical bound
/// AAD exceeds this limit cannot use the admitted custody path.
pub const MAX_KEY_CUSTODY_BOUND_AAD_BYTES: usize = 64 * 1024;

/// Capabilities every admitted provider-owned sealed-custody module requires.
///
/// A policy must explicitly require the module to declare, self-test, and
/// service both `SealedKeyStorage` and `Zeroization`. The composite module
/// structurally binds that evidence to the remote-seal operations, but the SDK
/// does not independently certify either provider declaration.
pub const fn key_custody_required_capabilities() -> CapabilitySet {
    CapabilitySet::empty()
        .with(CryptoCapability::Zeroization)
        .with(CryptoCapability::SealedKeyStorage)
}

/// One exact module supplying both capability evidence and non-exportable
/// remote-seal operations.
///
/// This composite trait prevents admission evidence from one object from being
/// paired with operations on another. Implementations declaring
/// `SealedKeyStorage` promise to keep key material behind their provider
/// boundary and return only ciphertext or zeroizing plaintext; the SDK records
/// and gates on that declaration without independently certifying it.
pub trait KeyCustodyModule: CryptoModule + RemoteSealProvider {}

impl<T> KeyCustodyModule for T where T: CryptoModule + RemoteSealProvider {}

/// Fail-closed error while probing and installing the process key-custody
/// module.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCustodyInstallError {
    /// The caller's policy omitted one or more mandatory custody capabilities.
    PolicyMissingCapabilities {
        /// Mandatory capabilities omitted by the policy.
        missing: CapabilitySet,
    },
    /// The module's admission-time report did not satisfy the policy.
    PolicyRejected(PolicyError),
    /// Identity or validation changed, or a granted capability was no longer
    /// advertised or serviceable, before atomic installation.
    EvidenceChanged,
    /// A module is already installed; the process slot is immutable.
    AlreadyInstalled,
}

impl KeyCustodyInstallError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PolicyMissingCapabilities { .. } => {
                "key_custody_install_policy_missing_capabilities"
            }
            Self::PolicyRejected(_) => "key_custody_install_policy_rejected",
            Self::EvidenceChanged => "key_custody_install_evidence_changed",
            Self::AlreadyInstalled => "key_custody_install_already_installed",
        }
    }
}

impl fmt::Display for KeyCustodyInstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for KeyCustodyInstallError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PolicyRejected(error) => Some(error),
            Self::PolicyMissingCapabilities { .. }
            | Self::EvidenceChanged
            | Self::AlreadyInstalled => None,
        }
    }
}

struct AdmittedKeyCustodyModule {
    module: Arc<dyn KeyCustodyModule>,
    admission: PolicyAdmission,
    report: CapabilityReport,
}

static KEY_CUSTODY_MODULE: OnceLock<AdmittedKeyCustodyModule> = OnceLock::new();

/// Opaque handle to the process's admitted non-exportable key-custody module.
///
/// The handle has no public constructor or `Default`; obtain it through
/// [`admitted_key_custody`] only after [`install_key_custody_module`] succeeds.
/// It contains no provider endpoint, key identifier, tenant, or key material.
///
/// Direct [`RemoteSealProvider`] implementations remain available for ordinary
/// unadmitted compatibility use, but they cannot construct this handle or
/// inherit its admission evidence.
///
/// ```compile_fail
/// use opc_key::AdmittedKeyCustody;
///
/// let _forged = AdmittedKeyCustody { _private: () };
/// ```
#[derive(Clone, Copy)]
pub struct AdmittedKeyCustody {
    _private: (),
}

impl fmt::Debug for AdmittedKeyCustody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedKeyCustody")
            .finish_non_exhaustive()
    }
}

impl AdmittedKeyCustody {
    /// Admission-time bounded capability evidence for the installed module.
    ///
    /// This is the report whose self-test evidence was admitted at startup.
    /// It is an immutable snapshot, not a live readiness report. Every seal and
    /// unseal separately rechecks current identity, validation declaration,
    /// advertisement, and serviceable capabilities.
    pub fn admission_report(&self) -> Result<CapabilityReport, KeyCustodyOperationError> {
        installed_module(&KEY_CUSTODY_MODULE).map(|installed| installed.report.clone())
    }
}

/// Probe, admit, and atomically install the process key-custody module.
///
/// The returned [`CapabilityReport`] is the exact bounded admission-time
/// evidence stored with the immutable slot. A successful return does not itself
/// provide an operation handle; call [`admitted_key_custody`] after security
/// initialization to obtain the non-forgeable adapter.
///
/// Self-test evidence is admission-time evidence. Operations do not rerun an
/// asynchronous power-on self-test. Instead, every operation synchronously
/// rechecks the complete granted capability set against the same module's live
/// advertisement and readiness snapshot. A module whose later health or
/// self-test state becomes invalid must withdraw the affected capabilities
/// through [`CryptoModule::readiness`].
///
/// # Errors
///
/// Fails when the policy omits a mandatory capability, the probed report is
/// rejected, the module no longer matches the admitted identity, validation,
/// or granted-capability evidence before installation, or the process slot was
/// already installed. A failed attempt leaves an empty slot available for a
/// corrected configuration unless another caller won the installation race.
///
/// A direct remote-seal trait object remains an unadmitted compatibility path;
/// it cannot be converted into an admitted module without the same object also
/// implementing [`CryptoModule`].
///
/// ```compile_fail
/// use std::sync::Arc;
///
/// use opc_key::{install_key_custody_module, ProviderPolicy, RemoteSealProvider};
///
/// async fn cannot_admit_direct_only(provider: Arc<dyn RemoteSealProvider>) {
///     let _ = install_key_custody_module(provider, ProviderPolicy::new()).await;
/// }
/// ```
pub async fn install_key_custody_module(
    module: Arc<dyn KeyCustodyModule>,
    policy: ProviderPolicy,
) -> Result<CapabilityReport, KeyCustodyInstallError> {
    let required = key_custody_required_capabilities();
    let missing = required.difference(policy.required_capabilities());
    if !missing.is_empty() {
        return Err(KeyCustodyInstallError::PolicyMissingCapabilities { missing });
    }
    if KEY_CUSTODY_MODULE.get().is_some() {
        return Err(KeyCustodyInstallError::AlreadyInstalled);
    }

    let report = probe_capability_report(module.as_ref()).await;
    install_key_custody_module_with_report(&KEY_CUSTODY_MODULE, module, policy, report)
}

/// Obtain the process's admitted non-exportable key-custody handle.
///
/// This performs the same live synchronous evidence checks as an operation.
/// An already-issued handle remains inert if capabilities are later withdrawn:
/// each operation checks again before dispatch.
pub fn admitted_key_custody() -> Result<AdmittedKeyCustody, KeyCustodyOperationError> {
    select_module(&KEY_CUSTODY_MODULE)?;
    Ok(AdmittedKeyCustody { _private: () })
}

fn install_key_custody_module_with_report(
    slot: &OnceLock<AdmittedKeyCustodyModule>,
    module: Arc<dyn KeyCustodyModule>,
    policy: ProviderPolicy,
    report: CapabilityReport,
) -> Result<CapabilityReport, KeyCustodyInstallError> {
    let required = key_custody_required_capabilities();
    let missing = required.difference(policy.required_capabilities());
    if !missing.is_empty() {
        return Err(KeyCustodyInstallError::PolicyMissingCapabilities { missing });
    }

    let admission = policy
        .admit(&report)
        .map_err(KeyCustodyInstallError::PolicyRejected)?;
    let granted = admission.granted_capabilities();
    if module.identity() != *admission.identity()
        || module.validation_state() != *admission.validation_state()
        || !module.advertised_capabilities().contains_all(granted)
        || !module
            .readiness()
            .serviceable_capabilities()
            .contains_all(granted)
    {
        return Err(KeyCustodyInstallError::EvidenceChanged);
    }

    let returned_report = report.clone();
    slot.set(AdmittedKeyCustodyModule {
        module,
        admission,
        report,
    })
    .map_err(|_| KeyCustodyInstallError::AlreadyInstalled)?;
    Ok(returned_report)
}

fn installed_module(
    slot: &OnceLock<AdmittedKeyCustodyModule>,
) -> Result<&AdmittedKeyCustodyModule, KeyCustodyOperationError> {
    slot.get().ok_or(KeyCustodyOperationError::NotInstalled)
}

fn verify_admission(installed: &AdmittedKeyCustodyModule) -> Result<(), KeyCustodyOperationError> {
    let granted = installed.admission.granted_capabilities();
    if installed.module.identity() != *installed.admission.identity() {
        return Err(KeyCustodyOperationError::IdentityChanged);
    }
    if installed.module.validation_state() != *installed.admission.validation_state() {
        return Err(KeyCustodyOperationError::ValidationChanged);
    }
    if !granted.contains_all(key_custody_required_capabilities()) {
        return Err(KeyCustodyOperationError::CapabilityNotAdmitted);
    }
    if !installed
        .module
        .advertised_capabilities()
        .contains_all(granted)
        || !installed
            .module
            .readiness()
            .serviceable_capabilities()
            .contains_all(granted)
    {
        return Err(KeyCustodyOperationError::CapabilityWithdrawn);
    }
    Ok(())
}

fn select_module(
    slot: &OnceLock<AdmittedKeyCustodyModule>,
) -> Result<&AdmittedKeyCustodyModule, KeyCustodyOperationError> {
    let installed = installed_module(slot)?;
    verify_admission(installed)?;
    Ok(installed)
}

async fn seal_with_slot(
    slot: &OnceLock<AdmittedKeyCustodyModule>,
    aad: &EnvelopeAad,
    plaintext: &[u8],
) -> Result<EncryptedPayload, KeyError> {
    let installed = select_module(slot).map_err(KeyError::from)?;
    let payload = installed
        .module
        .seal(aad, plaintext)
        .await
        .map_err(map_provider_error)?;
    validate_provider_payload(aad, payload)
}

async fn unseal_with_slot(
    slot: &OnceLock<AdmittedKeyCustodyModule>,
    key_id: &KeyId,
    aad: &EnvelopeAad,
    ciphertext_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let installed = select_module(slot).map_err(KeyError::from)?;
    installed
        .module
        .unseal(key_id, aad, ciphertext_and_tag)
        .await
        .map_err(map_provider_error)
}

fn map_provider_error(error: KeyError) -> KeyError {
    match error {
        KeyError::NotFound => KeyError::NotFound,
        KeyError::Unavailable => KeyError::Unavailable,
        _ => KeyCustodyOperationError::ProviderOperationFailed.into(),
    }
}

fn validate_provider_payload(
    expected_aad: &EnvelopeAad,
    payload: EncryptedPayload,
) -> Result<EncryptedPayload, KeyError> {
    if payload.aad.len() > MAX_KEY_CUSTODY_BOUND_AAD_BYTES {
        return Err(KeyCustodyOperationError::InvalidProviderOutput.into());
    }

    let (decoded_aad, returned_key_id) = decode_bound_aad(&payload.aad)
        .map_err(|_| KeyError::from(KeyCustodyOperationError::InvalidProviderOutput))?;
    if &decoded_aad != expected_aad {
        return Err(KeyCustodyOperationError::InvalidProviderOutput.into());
    }

    let exact = serialize_bound_aad(expected_aad, &returned_key_id)
        .map_err(|_| KeyError::from(KeyCustodyOperationError::InvalidProviderOutput))?;
    if exact != payload.aad {
        return Err(KeyCustodyOperationError::InvalidProviderOutput.into());
    }
    Ok(payload)
}

#[async_trait]
impl RemoteSealProvider for AdmittedKeyCustody {
    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        seal_with_slot(&KEY_CUSTODY_MODULE, aad, plaintext).await
    }

    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        unseal_with_slot(&KEY_CUSTODY_MODULE, key_id, aad, ciphertext_and_tag).await
    }
}

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;
