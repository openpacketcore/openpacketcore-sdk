//! Process-level IKEv2 cryptographic-module admission and operation routing.
//!
//! The selected module is installed exactly once after its evidence, policy,
//! and configured algorithm set have all passed validation. Every IKEv2
//! cryptographic operation rechecks the immutable admission against the same
//! module object's current identity, validation declaration, advertised
//! capabilities, and readiness. There is no production fallback.

use std::{
    error::Error,
    fmt,
    sync::{Arc, OnceLock},
};

use opc_crypto_provider::{
    probe_capability_report, CapabilityReport, CapabilitySet, CryptoCapability,
    CryptoOperationError, CryptoOperationErrorCode, IkeAeadAlgorithm, IkeCbcAlgorithm,
    IkeCryptoModule, IkeDhGroup, IkeDhKeyPair, IkeHashAlgorithm, IkeIntegrityAlgorithm,
    IkePrfAlgorithm, IkeSignatureAlgorithm, IkeSigningKey, PolicyAdmission, PolicyError,
    ProviderPolicy,
};
use zeroize::Zeroizing;

use crate::sa_init_crypto::{
    validate_dh_public_value, Ikev2ChildSaCryptoProfile, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm, Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile,
};

/// The configured IKEv2 algorithms that must be executable before startup.
///
/// Values are deduplicated as they are added. An algorithm is usable only when
/// it appears here, passed provider preflight, and its capability remains
/// admitted and ready at operation time.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Ikev2CryptoRequirements {
    prfs: Vec<Ikev2PrfAlgorithm>,
    integrities: Vec<Ikev2IntegrityAlgorithm>,
    encryptions: Vec<Ikev2EncryptionAlgorithm>,
    dh_groups: Vec<Ikev2DhGroup>,
    signature_verification: Vec<IkeSignatureAlgorithm>,
    signature_generation: Vec<IkeSignatureAlgorithm>,
    nat_detection: bool,
    certreq_authority_hash: bool,
}

impl Ikev2CryptoRequirements {
    /// Begin with no admitted algorithms.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            prfs: Vec::new(),
            integrities: Vec::new(),
            encryptions: Vec::new(),
            dh_groups: Vec::new(),
            signature_verification: Vec::new(),
            signature_generation: Vec::new(),
            nat_detection: false,
            certreq_authority_hash: false,
        }
    }

    /// Require every algorithm the SDK software module implements in this
    /// build. This is primarily useful for SDK integration tests; deployments
    /// should normally enumerate their configured profiles instead.
    #[must_use]
    pub fn all_software_supported() -> Self {
        let mut requirements = Self::new();
        for prf in [
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2PrfAlgorithm::HmacSha2_384,
            Ikev2PrfAlgorithm::HmacSha2_512,
        ] {
            requirements.add_prf(prf);
        }
        for integrity in [
            Ikev2IntegrityAlgorithm::HmacSha2_256_128,
            Ikev2IntegrityAlgorithm::HmacSha2_384_192,
            Ikev2IntegrityAlgorithm::HmacSha2_512_256,
        ] {
            requirements.add_integrity(integrity);
        }
        for encryption in [
            Ikev2EncryptionAlgorithm::AesCbc128,
            Ikev2EncryptionAlgorithm::AesCbc192,
            Ikev2EncryptionAlgorithm::AesCbc256,
            Ikev2EncryptionAlgorithm::AesGcm16_128,
            Ikev2EncryptionAlgorithm::AesGcm16_192,
            Ikev2EncryptionAlgorithm::AesGcm16_256,
        ] {
            requirements.add_encryption(encryption);
        }
        for group in [
            Ikev2DhGroup::Modp2048,
            Ikev2DhGroup::Ecp256,
            Ikev2DhGroup::Ecp384,
            Ikev2DhGroup::Ecp521,
        ] {
            requirements.add_dh_group(group);
        }
        requirements.require_signature(IkeSignatureAlgorithm::EcdsaP256Sha2_256);
        requirements.require_signature(IkeSignatureAlgorithm::EcdsaP384Sha2_256);
        requirements.require_signature(IkeSignatureAlgorithm::EcdsaP384Sha2_384);
        requirements.require_signature_verification(IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256);
        #[cfg(feature = "rsa-signing")]
        requirements.require_signature_generation(IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256);
        requirements.require_nat_detection();
        requirements.require_certreq_authority_hash();
        requirements
    }

    /// Add every operation required by one executable IKE-SA profile.
    ///
    /// # Errors
    ///
    /// Returns [`Ikev2SaInitCryptoError`] if the profile itself is not an
    /// executable IKE-SA transform combination.
    pub fn require_ike_sa_profile(
        &mut self,
        profile: Ikev2SaInitCryptoProfile,
    ) -> Result<&mut Self, Ikev2SaInitCryptoError> {
        profile.validate_executable()?;
        self.add_prf(profile.prf());
        self.add_dh_group(profile.dh_group());
        self.add_encryption(profile.encryption());
        if let Some(integrity) = profile.integrity() {
            self.add_integrity(integrity);
        }
        Ok(self)
    }

    /// Add the PRF required to derive KEYMAT for one Child-SA profile.
    ///
    /// ESP encryption and integrity execution is product/dataplane-owned; the
    /// SDK operation performed for this profile is RFC 7296 PRF+ only.
    pub fn require_child_sa_profile(&mut self, profile: Ikev2ChildSaCryptoProfile) -> &mut Self {
        self.add_prf(profile.prf());
        self
    }

    /// Add the DH group required by a Child-SA PFS exchange.
    ///
    /// [`Ikev2ChildSaCryptoProfile`] describes the ESP algorithms whose
    /// KEYMAT the IKE-SA PRF derives; the optional CREATE_CHILD_SA PFS group
    /// is negotiated separately. Call this for every configured Child-SA DH
    /// group so startup admission proves both key generation and agreement
    /// before traffic is accepted.
    pub fn require_child_sa_pfs_group(&mut self, group: Ikev2DhGroup) -> &mut Self {
        self.add_dh_group(group);
        self
    }

    /// Add an IKE_AUTH algorithm for both signing and verification.
    ///
    /// Use [`Self::require_signature_verification`] when a deployment only
    /// verifies peer signatures and does not possess a private signing key for
    /// the algorithm.
    pub fn require_signature(&mut self, algorithm: IkeSignatureAlgorithm) -> &mut Self {
        self.require_signature_verification(algorithm);
        self.require_signature_generation(algorithm);
        self
    }

    /// Add an IKE_AUTH peer-signature verification algorithm.
    pub fn require_signature_verification(
        &mut self,
        algorithm: IkeSignatureAlgorithm,
    ) -> &mut Self {
        push_unique(&mut self.signature_verification, algorithm);
        self
    }

    /// Add an IKE_AUTH private-key signature generation algorithm.
    pub fn require_signature_generation(&mut self, algorithm: IkeSignatureAlgorithm) -> &mut Self {
        push_unique(&mut self.signature_generation, algorithm);
        self
    }

    /// Require RFC 7296 NAT-detection SHA-1 hashing.
    pub const fn require_nat_detection(&mut self) -> &mut Self {
        self.nat_detection = true;
        self
    }

    /// Require RFC 7296 section 3.7 CERTREQ Certification Authority hashing.
    ///
    /// This requirement is deliberately independent of
    /// [`Self::require_nat_detection`]. Both operations use SHA-1 through the
    /// admitted [`CryptoCapability::IkeHash`] capability, but authorizing one
    /// protocol use does not authorize the other.
    pub const fn require_certreq_authority_hash(&mut self) -> &mut Self {
        self.certreq_authority_hash = true;
        self
    }

    /// Capabilities derived from the configured algorithms.
    #[must_use = "the derived capability set must be included in provider policy"]
    pub fn required_capabilities(&self) -> CapabilitySet {
        let mut capabilities = CapabilitySet::empty();
        if !self.prfs.is_empty() {
            capabilities = capabilities.with(CryptoCapability::IkePrf);
        }
        if self.nat_detection || self.certreq_authority_hash {
            capabilities = capabilities.with(CryptoCapability::IkeHash);
        }
        if !self.integrities.is_empty() {
            capabilities = capabilities.with(CryptoCapability::IkeIntegrity);
        }
        if !self.encryptions.is_empty() {
            capabilities = capabilities.with(CryptoCapability::IkeEncryption);
            if self
                .encryptions
                .iter()
                .any(|algorithm| !algorithm.is_aead())
            {
                capabilities = capabilities.with(CryptoCapability::ApprovedEntropy);
            }
        }
        if !self.dh_groups.is_empty() {
            capabilities = capabilities
                .with(CryptoCapability::IkeDiffieHellman)
                .with(CryptoCapability::ApprovedEntropy);
        }
        if !self.signature_verification.is_empty() || !self.signature_generation.is_empty() {
            capabilities = capabilities.with(CryptoCapability::IkeSignature);
        }
        if !capabilities.is_empty() {
            capabilities = capabilities.with(CryptoCapability::Zeroization);
        }
        capabilities
    }

    fn is_empty(&self) -> bool {
        self.required_capabilities().is_empty()
    }

    fn add_prf(&mut self, algorithm: Ikev2PrfAlgorithm) {
        push_unique(&mut self.prfs, algorithm);
    }

    fn add_integrity(&mut self, algorithm: Ikev2IntegrityAlgorithm) {
        push_unique(&mut self.integrities, algorithm);
    }

    fn add_encryption(&mut self, algorithm: Ikev2EncryptionAlgorithm) {
        push_unique(&mut self.encryptions, algorithm);
    }

    fn add_dh_group(&mut self, group: Ikev2DhGroup) {
        push_unique(&mut self.dh_groups, group);
    }
}

fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

/// Stable machine-readable process-level module error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ikev2CryptoModuleErrorCode {
    /// No module has been installed in this process.
    NotInstalled,
    /// The module identity changed after admission.
    IdentityChanged,
    /// The module validation declaration changed after admission.
    ValidationChanged,
    /// The required capability was not granted by policy.
    CapabilityNotAdmitted,
    /// An admitted capability was withdrawn or is no longer advertised.
    CapabilityWithdrawn,
    /// The operation's algorithm was not included in startup preflight.
    AlgorithmNotAdmitted,
    /// The admitted module no longer reports support for the algorithm.
    AlgorithmUnsupported,
    /// The admitted module rejected or failed the operation.
    OperationFailed,
    /// A successful provider response violated the operation contract.
    InvalidOutput,
}

impl Ikev2CryptoModuleErrorCode {
    /// Stable machine-readable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotInstalled => "ike_crypto_module_not_installed",
            Self::IdentityChanged => "ike_crypto_module_identity_changed",
            Self::ValidationChanged => "ike_crypto_module_validation_changed",
            Self::CapabilityNotAdmitted => "ike_crypto_module_capability_not_admitted",
            Self::CapabilityWithdrawn => "ike_crypto_module_capability_withdrawn",
            Self::AlgorithmNotAdmitted => "ike_crypto_module_algorithm_not_admitted",
            Self::AlgorithmUnsupported => "ike_crypto_module_algorithm_unsupported",
            Self::OperationFailed => "ike_crypto_module_operation_failed",
            Self::InvalidOutput => "ike_crypto_module_invalid_output",
        }
    }
}

impl fmt::Display for Ikev2CryptoModuleErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Fail-closed error from a routed IKEv2 cryptographic operation.
///
/// Formatting exposes stable codes only. Provider-native diagnostics never
/// cross this boundary.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ikev2CryptoModuleError {
    code: Ikev2CryptoModuleErrorCode,
    operation_code: Option<CryptoOperationErrorCode>,
}

impl Ikev2CryptoModuleError {
    const fn new(code: Ikev2CryptoModuleErrorCode) -> Self {
        Self {
            code,
            operation_code: None,
        }
    }

    const fn operation(error: &CryptoOperationError) -> Self {
        Self::from_operation_code(error.code())
    }

    const fn from_operation_code(operation_code: CryptoOperationErrorCode) -> Self {
        Self {
            code: Ikev2CryptoModuleErrorCode::OperationFailed,
            operation_code: Some(operation_code),
        }
    }

    pub(crate) const fn invalid_output() -> Self {
        Self::new(Ikev2CryptoModuleErrorCode::InvalidOutput)
    }

    /// Stable machine-readable boundary error code.
    #[must_use]
    pub const fn code(self) -> Ikev2CryptoModuleErrorCode {
        self.code
    }

    /// Stable provider operation code, when the module executed and failed.
    #[must_use]
    pub const fn operation_code(self) -> Option<CryptoOperationErrorCode> {
        self.operation_code
    }

    /// Stable machine-readable boundary error string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.code.as_str()
    }
}

impl fmt::Debug for Ikev2CryptoModuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ikev2CryptoModuleError")
            .field("code", &self.code.as_str())
            .field(
                "operation_code",
                &self.operation_code.map(CryptoOperationErrorCode::as_str),
            )
            .finish()
    }
}

impl fmt::Display for Ikev2CryptoModuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl Error for Ikev2CryptoModuleError {}

/// Fail-closed error while preflighting and installing the process module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2CryptoModuleInstallError {
    /// No algorithms were configured, so an operation admission would be
    /// meaningless and dangerously underspecified.
    EmptyRequirements,
    /// The caller's provider policy did not require all derived capabilities.
    PolicyMissingCapabilities {
        /// Capabilities the policy omitted.
        missing: CapabilitySet,
    },
    /// The probed report did not satisfy the caller's policy.
    PolicyRejected(PolicyError),
    /// One configured algorithm is not executable by this module.
    AlgorithmUnsupported {
        /// Stable redaction-safe algorithm code.
        algorithm: &'static str,
    },
    /// Evidence changed between probe/admission and atomic installation.
    EvidenceChanged,
    /// A module was already installed; the immutable slot cannot be replaced.
    AlreadyInstalled,
    /// The SDK software module's built-in bounded identity could not be built.
    SoftwareIdentityInvalid,
}

impl Ikev2CryptoModuleInstallError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyRequirements => "ike_crypto_install_empty_requirements",
            Self::PolicyMissingCapabilities { .. } => {
                "ike_crypto_install_policy_missing_capabilities"
            }
            Self::PolicyRejected(_) => "ike_crypto_install_policy_rejected",
            Self::AlgorithmUnsupported { .. } => "ike_crypto_install_algorithm_unsupported",
            Self::EvidenceChanged => "ike_crypto_install_evidence_changed",
            Self::AlreadyInstalled => "ike_crypto_install_already_installed",
            Self::SoftwareIdentityInvalid => "ike_crypto_install_software_identity_invalid",
        }
    }
}

impl fmt::Display for Ikev2CryptoModuleInstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Error for Ikev2CryptoModuleInstallError {}

struct AdmittedIkev2CryptoModule {
    module: Arc<dyn IkeCryptoModule>,
    admission: PolicyAdmission,
    requirements: Ikev2CryptoRequirements,
}

static IKEV2_CRYPTO_MODULE: OnceLock<AdmittedIkev2CryptoModule> = OnceLock::new();

struct ModuleSelection(&'static AdmittedIkev2CryptoModule);

impl ModuleSelection {
    fn module(&self) -> &dyn IkeCryptoModule {
        self.0.module.as_ref()
    }

    fn prf_admitted(&self, algorithm: Ikev2PrfAlgorithm) -> bool {
        self.0.requirements.prfs.contains(&algorithm)
    }

    fn integrity_admitted(&self, algorithm: Ikev2IntegrityAlgorithm) -> bool {
        self.0.requirements.integrities.contains(&algorithm)
    }

    fn encryption_admitted(&self, algorithm: Ikev2EncryptionAlgorithm) -> bool {
        self.0.requirements.encryptions.contains(&algorithm)
    }

    fn dh_admitted(&self, group: Ikev2DhGroup) -> bool {
        self.0.requirements.dh_groups.contains(&group)
    }

    fn signature_verification_admitted(&self, algorithm: IkeSignatureAlgorithm) -> bool {
        self.0
            .requirements
            .signature_verification
            .contains(&algorithm)
    }

    fn signature_generation_admitted(&self, algorithm: IkeSignatureAlgorithm) -> bool {
        self.0
            .requirements
            .signature_generation
            .contains(&algorithm)
    }

    fn nat_detection_admitted(&self) -> bool {
        self.0.requirements.nat_detection
    }

    fn certreq_authority_hash_admitted(&self) -> bool {
        self.0.requirements.certreq_authority_hash
    }
}

/// Probe, preflight, admit, and atomically install the process IKEv2 module.
///
/// Call this from `opc_runtime::StartupPhases::init_security` before any
/// runtime-mediated listener binds. A failed probe or preflight leaves the
/// once-only slot unset so startup code may report the failure or deliberately
/// attempt a corrected configuration. After success the module cannot be
/// replaced or removed for the lifetime of the process.
///
/// # Errors
///
/// Returns [`Ikev2CryptoModuleInstallError`] when requirements are empty, the
/// policy is insufficient, evidence or algorithm support is insufficient or
/// changes during admission, or a module is already installed.
pub async fn install_ikev2_crypto_module(
    module: Arc<dyn IkeCryptoModule>,
    policy: ProviderPolicy,
    requirements: Ikev2CryptoRequirements,
) -> Result<CapabilityReport, Ikev2CryptoModuleInstallError> {
    let report = probe_capability_report(module.as_ref()).await;
    install_ikev2_crypto_module_with_report(module, policy, requirements, report)
}

pub(crate) fn install_ikev2_crypto_module_with_report(
    module: Arc<dyn IkeCryptoModule>,
    policy: ProviderPolicy,
    requirements: Ikev2CryptoRequirements,
    report: CapabilityReport,
) -> Result<CapabilityReport, Ikev2CryptoModuleInstallError> {
    if requirements.is_empty() {
        return Err(Ikev2CryptoModuleInstallError::EmptyRequirements);
    }
    let required = requirements.required_capabilities();
    let missing_from_policy = required.difference(policy.required_capabilities());
    if !missing_from_policy.is_empty() {
        return Err(Ikev2CryptoModuleInstallError::PolicyMissingCapabilities {
            missing: missing_from_policy,
        });
    }
    validate_algorithm_support(module.as_ref(), &requirements)?;
    let admission = policy
        .admit(&report)
        .map_err(Ikev2CryptoModuleInstallError::PolicyRejected)?;
    let granted = admission.granted_capabilities();

    if module.identity() != *admission.identity()
        || module.validation_state() != *admission.validation_state()
        || !module.advertised_capabilities().contains_all(granted)
        || !module
            .readiness()
            .serviceable_capabilities()
            .contains_all(granted)
    {
        return Err(Ikev2CryptoModuleInstallError::EvidenceChanged);
    }
    validate_algorithm_support(module.as_ref(), &requirements)?;

    IKEV2_CRYPTO_MODULE
        .set(AdmittedIkev2CryptoModule {
            module,
            admission,
            requirements,
        })
        .map_err(|_| Ikev2CryptoModuleInstallError::AlreadyInstalled)?;
    Ok(report)
}

fn validate_algorithm_support(
    module: &dyn IkeCryptoModule,
    requirements: &Ikev2CryptoRequirements,
) -> Result<(), Ikev2CryptoModuleInstallError> {
    for algorithm in requirements.prfs.iter().copied() {
        let mapped = map_prf(algorithm);
        if !module.supports_prf(mapped) {
            return Err(unsupported_install(mapped.as_str()));
        }
    }
    for algorithm in requirements.integrities.iter().copied() {
        let mapped = map_integrity(algorithm);
        if !module.supports_integrity(mapped) {
            return Err(unsupported_install(mapped.as_str()));
        }
    }
    for algorithm in requirements.encryptions.iter().copied() {
        match map_encryption(algorithm) {
            None => return Err(unsupported_install("encr_null")),
            Some(MappedEncryption::Aead(mapped)) if !module.supports_aead(mapped) => {
                return Err(unsupported_install(mapped.as_str()));
            }
            Some(MappedEncryption::Cbc(mapped)) if !module.supports_cbc(mapped) => {
                return Err(unsupported_install(mapped.as_str()));
            }
            Some(MappedEncryption::Aead(_) | MappedEncryption::Cbc(_)) => {}
        }
    }
    for group in requirements.dh_groups.iter().copied() {
        let mapped = map_dh_group(group);
        if !module.supports_dh_group(mapped) {
            return Err(unsupported_install(mapped.as_str()));
        }
    }
    for algorithm in requirements.signature_verification.iter().copied() {
        if !module.supports_signature_verification(algorithm) {
            return Err(unsupported_install(algorithm.as_str()));
        }
    }
    for algorithm in requirements.signature_generation.iter().copied() {
        if !module.supports_signature_generation(algorithm) {
            return Err(unsupported_install(algorithm.as_str()));
        }
    }
    if (requirements.nat_detection || requirements.certreq_authority_hash)
        && !module.supports_hash(IkeHashAlgorithm::Sha1)
    {
        return Err(unsupported_install(IkeHashAlgorithm::Sha1.as_str()));
    }
    Ok(())
}

const fn unsupported_install(algorithm: &'static str) -> Ikev2CryptoModuleInstallError {
    Ikev2CryptoModuleInstallError::AlgorithmUnsupported { algorithm }
}

fn verify_admission(
    installed: &AdmittedIkev2CryptoModule,
    capability: CryptoCapability,
) -> Result<(), Ikev2CryptoModuleError> {
    let required = installed.requirements.required_capabilities();
    let granted = installed.admission.granted_capabilities();
    if installed.module.identity() != *installed.admission.identity() {
        return Err(Ikev2CryptoModuleError::new(
            Ikev2CryptoModuleErrorCode::IdentityChanged,
        ));
    }
    if installed.module.validation_state() != *installed.admission.validation_state() {
        return Err(Ikev2CryptoModuleError::new(
            Ikev2CryptoModuleErrorCode::ValidationChanged,
        ));
    }
    if !required.contains(capability) || !granted.contains_all(required) {
        return Err(Ikev2CryptoModuleError::new(
            Ikev2CryptoModuleErrorCode::CapabilityNotAdmitted,
        ));
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
        return Err(Ikev2CryptoModuleError::new(
            Ikev2CryptoModuleErrorCode::CapabilityWithdrawn,
        ));
    }
    Ok(())
}

fn select_module(capability: CryptoCapability) -> Result<ModuleSelection, Ikev2CryptoModuleError> {
    let installed = IKEV2_CRYPTO_MODULE
        .get()
        .ok_or_else(|| Ikev2CryptoModuleError::new(Ikev2CryptoModuleErrorCode::NotInstalled))?;
    verify_admission(installed, capability)?;
    Ok(ModuleSelection(installed))
}

pub(crate) fn execute_prf(
    algorithm: Ikev2PrfAlgorithm,
    key: &[u8],
    data: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkePrf)?;
    if !selected.prf_admitted(algorithm) {
        return Err(algorithm_not_admitted());
    }
    let mapped = map_prf(algorithm);
    if !selected.module().supports_prf(mapped) {
        return Err(algorithm_unsupported());
    }
    let output = selected
        .module()
        .prf(mapped, key, data)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    validate_output_len(output.len(), mapped.output_len())?;
    Ok(output)
}

pub(crate) fn execute_prf_plus(
    algorithm: Ikev2PrfAlgorithm,
    key: &[u8],
    seed: &[u8],
    output_len: usize,
) -> Result<Zeroizing<Vec<u8>>, Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkePrf)?;
    if !selected.prf_admitted(algorithm) {
        return Err(algorithm_not_admitted());
    }
    let mapped = map_prf(algorithm);
    if !selected.module().supports_prf(mapped) {
        return Err(algorithm_unsupported());
    }
    let output = selected
        .module()
        .prf_plus(mapped, key, seed, output_len)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    validate_output_len(output.len(), output_len)?;
    Ok(output)
}

pub(crate) fn execute_integrity_checksum(
    algorithm: Ikev2IntegrityAlgorithm,
    key: &[u8],
    message_prefix: &[u8],
    message_suffix: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkeIntegrity)?;
    if !selected.integrity_admitted(algorithm) {
        return Err(algorithm_not_admitted());
    }
    let mapped = map_integrity(algorithm);
    if !selected.module().supports_integrity(mapped) {
        return Err(algorithm_unsupported());
    }
    let output = selected
        .module()
        .compute_integrity_checksum(mapped, key, message_prefix, message_suffix)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    validate_output_len(output.len(), mapped.icv_len())?;
    Ok(output)
}

pub(crate) fn execute_integrity_verification(
    algorithm: Ikev2IntegrityAlgorithm,
    key: &[u8],
    authenticated_message: &[u8],
    received_icv: &[u8],
) -> Result<(), Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkeIntegrity)?;
    if !selected.integrity_admitted(algorithm) {
        return Err(algorithm_not_admitted());
    }
    let mapped = map_integrity(algorithm);
    if !selected.module().supports_integrity(mapped) {
        return Err(algorithm_unsupported());
    }
    selected
        .module()
        .verify_integrity_checksum(mapped, key, authenticated_message, received_icv)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))
}

fn select_encryption(
    algorithm: Ikev2EncryptionAlgorithm,
) -> Result<(ModuleSelection, MappedEncryption), Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkeEncryption)?;
    if !selected.encryption_admitted(algorithm) {
        return Err(algorithm_not_admitted());
    }
    let mapped = map_encryption(algorithm).ok_or_else(algorithm_unsupported)?;
    let supported = match mapped {
        MappedEncryption::Aead(value) => selected.module().supports_aead(value),
        MappedEncryption::Cbc(value) => selected.module().supports_cbc(value),
    };
    if !supported {
        return Err(algorithm_unsupported());
    }
    Ok((selected, mapped))
}

pub(crate) fn execute_aead_seal(
    algorithm: Ikev2EncryptionAlgorithm,
    key: &[u8],
    salt: &[u8],
    explicit_iv: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Ikev2CryptoModuleError> {
    let (selected, mapped) = select_encryption(algorithm)?;
    let MappedEncryption::Aead(mapped) = mapped else {
        return Err(algorithm_unsupported());
    };
    let output = selected
        .module()
        .seal_aead(mapped, key, salt, explicit_iv, associated_data, plaintext)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    let expected_len = mapped
        .explicit_iv_len()
        .checked_add(plaintext.len())
        .and_then(|len| len.checked_add(mapped.tag_len()))
        .ok_or_else(Ikev2CryptoModuleError::invalid_output)?;
    validate_output_len(output.len(), expected_len)?;
    let returned_explicit_iv = output
        .get(..mapped.explicit_iv_len())
        .ok_or_else(Ikev2CryptoModuleError::invalid_output)?;
    if returned_explicit_iv != explicit_iv {
        return Err(Ikev2CryptoModuleError::invalid_output());
    }
    Ok(output)
}

pub(crate) fn execute_aead_open(
    algorithm: Ikev2EncryptionAlgorithm,
    key: &[u8],
    salt: &[u8],
    associated_data: &[u8],
    protected_body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2CryptoModuleError> {
    let (selected, mapped) = select_encryption(algorithm)?;
    let MappedEncryption::Aead(mapped) = mapped else {
        return Err(algorithm_unsupported());
    };
    let output = selected
        .module()
        .open_aead(mapped, key, salt, associated_data, protected_body)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    let overhead = mapped
        .explicit_iv_len()
        .checked_add(mapped.tag_len())
        .ok_or_else(Ikev2CryptoModuleError::invalid_output)?;
    let expected_len = protected_body
        .len()
        .checked_sub(overhead)
        .ok_or_else(Ikev2CryptoModuleError::invalid_output)?;
    validate_output_len(output.len(), expected_len)?;
    Ok(output)
}

pub(crate) fn execute_cbc_encrypt(
    algorithm: Ikev2EncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Ikev2CryptoModuleError> {
    let (selected, mapped) = select_encryption(algorithm)?;
    let MappedEncryption::Cbc(mapped) = mapped else {
        return Err(algorithm_unsupported());
    };
    let output = selected
        .module()
        .encrypt_cbc(mapped, key, iv, plaintext)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    validate_output_len(output.len(), plaintext.len())?;
    Ok(output)
}

pub(crate) fn execute_cbc_decrypt(
    algorithm: Ikev2EncryptionAlgorithm,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2CryptoModuleError> {
    let (selected, mapped) = select_encryption(algorithm)?;
    let MappedEncryption::Cbc(mapped) = mapped else {
        return Err(algorithm_unsupported());
    };
    let output = selected
        .module()
        .decrypt_cbc(mapped, key, iv, ciphertext)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    validate_output_len(output.len(), ciphertext.len())?;
    Ok(output)
}

fn select_dh(group: Ikev2DhGroup) -> Result<(ModuleSelection, IkeDhGroup), Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkeDiffieHellman)?;
    if !selected.dh_admitted(group) {
        return Err(algorithm_not_admitted());
    }
    let mapped = map_dh_group(group);
    if !selected.module().supports_dh_group(mapped) {
        return Err(algorithm_unsupported());
    }
    Ok((selected, mapped))
}

pub(crate) fn execute_dh_generate(
    group: Ikev2DhGroup,
) -> Result<(Box<dyn IkeDhKeyPair>, Vec<u8>), Ikev2CryptoModuleError> {
    let (selected, mapped) = select_dh(group)?;
    let keypair = selected
        .module()
        .generate_keypair(mapped)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    if keypair.group() != mapped {
        return Err(Ikev2CryptoModuleError::invalid_output());
    }
    let public_value = keypair.public_value().to_vec();
    validate_output_len(public_value.len(), mapped.public_value_len())?;
    validate_dh_public_value(group, &public_value)
        .map_err(|_| Ikev2CryptoModuleError::invalid_output())?;
    Ok((keypair, public_value))
}

pub(crate) fn execute_dh_agree(
    group: Ikev2DhGroup,
    keypair: &dyn IkeDhKeyPair,
    expected_public_value: &[u8],
    peer_public_value: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2CryptoModuleError> {
    let (_selected, mapped) = select_dh(group)?;
    validate_dh_handle(mapped, keypair, expected_public_value)?;
    validate_dh_public_value(group, peer_public_value).map_err(|_| {
        Ikev2CryptoModuleError::from_operation_code(CryptoOperationErrorCode::InvalidPeerPublicKey)
    })?;
    let shared_secret = keypair
        .agree(peer_public_value)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    validate_output_len(shared_secret.len(), mapped.shared_secret_len())?;
    validate_dh_handle(mapped, keypair, expected_public_value)?;
    Ok(shared_secret)
}

pub(crate) fn with_signature_verification_operation<T>(
    algorithm: IkeSignatureAlgorithm,
    operation: impl FnOnce(&dyn IkeCryptoModule) -> Result<T, CryptoOperationError>,
) -> Result<T, Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkeSignature)?;
    if !selected.signature_verification_admitted(algorithm) {
        return Err(algorithm_not_admitted());
    }
    if !selected.module().supports_signature_verification(algorithm) {
        return Err(algorithm_unsupported());
    }
    operation(selected.module()).map_err(|error| Ikev2CryptoModuleError::operation(&error))
}

pub(crate) fn with_signature_generation_operation<T>(
    algorithm: IkeSignatureAlgorithm,
    operation: impl FnOnce(&dyn IkeCryptoModule) -> Result<T, CryptoOperationError>,
) -> Result<T, Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkeSignature)?;
    if !selected.signature_generation_admitted(algorithm) {
        return Err(algorithm_not_admitted());
    }
    if !selected.module().supports_signature_generation(algorithm) {
        return Err(algorithm_unsupported());
    }
    operation(selected.module()).map_err(|error| Ikev2CryptoModuleError::operation(&error))
}

pub(crate) fn execute_signing_key(
    algorithm: IkeSignatureAlgorithm,
    key: &dyn IkeSigningKey,
    message: &[u8],
) -> Result<Vec<u8>, Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkeSignature)?;
    if !selected.signature_generation_admitted(algorithm) {
        return Err(algorithm_not_admitted());
    }
    if !selected.module().supports_signature_generation(algorithm) {
        return Err(algorithm_unsupported());
    }
    let output_shape = signing_output_shape(algorithm, key)?;
    let signature = key
        .sign(message)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    if signing_output_shape(algorithm, key)? != output_shape {
        return Err(Ikev2CryptoModuleError::invalid_output());
    }
    validate_signature_output(output_shape, &signature)?;
    Ok(signature)
}

pub(crate) fn execute_nat_hash(
    parts: &[&[u8]],
) -> Result<Zeroizing<Vec<u8>>, Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkeHash)?;
    if !selected.nat_detection_admitted() {
        return Err(algorithm_not_admitted());
    }
    if !selected.module().supports_hash(IkeHashAlgorithm::Sha1) {
        return Err(algorithm_unsupported());
    }
    let output = selected
        .module()
        .hash(IkeHashAlgorithm::Sha1, parts)
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    validate_output_len(output.len(), IkeHashAlgorithm::Sha1.output_len())?;
    Ok(output)
}

pub(crate) fn execute_certreq_authority_hash(
    subject_public_key_info_der: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::IkeHash)?;
    if !selected.certreq_authority_hash_admitted() {
        return Err(algorithm_not_admitted());
    }
    if !selected.module().supports_hash(IkeHashAlgorithm::Sha1) {
        return Err(algorithm_unsupported());
    }
    let output = selected
        .module()
        .hash(IkeHashAlgorithm::Sha1, &[subject_public_key_info_der])
        .map_err(|error| Ikev2CryptoModuleError::operation(&error))?;
    validate_output_len(output.len(), IkeHashAlgorithm::Sha1.output_len())?;
    Ok(output)
}

pub(crate) fn with_entropy_operation(
    operation: impl FnOnce(&dyn IkeCryptoModule) -> Result<(), CryptoOperationError>,
) -> Result<(), Ikev2CryptoModuleError> {
    let selected = select_module(CryptoCapability::ApprovedEntropy)?;
    operation(selected.module()).map_err(|error| Ikev2CryptoModuleError::operation(&error))
}

fn validate_dh_handle(
    expected_group: IkeDhGroup,
    keypair: &dyn IkeDhKeyPair,
    expected_public_value: &[u8],
) -> Result<(), Ikev2CryptoModuleError> {
    let current_public_value = keypair.public_value();
    if keypair.group() != expected_group || current_public_value != expected_public_value {
        return Err(Ikev2CryptoModuleError::invalid_output());
    }
    Ok(())
}

fn validate_output_len(actual: usize, expected: usize) -> Result<(), Ikev2CryptoModuleError> {
    if actual != expected {
        return Err(Ikev2CryptoModuleError::invalid_output());
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SigningOutputShape {
    Rsa { modulus_len: usize },
    EcdsaP256,
    EcdsaP384,
}

fn signing_output_shape(
    algorithm: IkeSignatureAlgorithm,
    key: &dyn IkeSigningKey,
) -> Result<SigningOutputShape, Ikev2CryptoModuleError> {
    if key.algorithm() != algorithm {
        return Err(Ikev2CryptoModuleError::invalid_output());
    }

    match algorithm {
        IkeSignatureAlgorithm::RsaPkcs1V15Sha2_256 => {
            let modulus_len = key
                .rsa_modulus_len()
                .filter(|modulus_len| *modulus_len > 0)
                .ok_or_else(Ikev2CryptoModuleError::invalid_output)?;
            Ok(SigningOutputShape::Rsa { modulus_len })
        }
        IkeSignatureAlgorithm::EcdsaP256Sha2_256 => {
            if key.rsa_modulus_len().is_some() {
                return Err(Ikev2CryptoModuleError::invalid_output());
            }
            Ok(SigningOutputShape::EcdsaP256)
        }
        IkeSignatureAlgorithm::EcdsaP384Sha2_256 | IkeSignatureAlgorithm::EcdsaP384Sha2_384 => {
            if key.rsa_modulus_len().is_some() {
                return Err(Ikev2CryptoModuleError::invalid_output());
            }
            Ok(SigningOutputShape::EcdsaP384)
        }
        _ => Err(algorithm_unsupported()),
    }
}

fn validate_signature_output(
    output_shape: SigningOutputShape,
    signature: &[u8],
) -> Result<(), Ikev2CryptoModuleError> {
    if signature.is_empty() {
        return Err(Ikev2CryptoModuleError::invalid_output());
    }

    let valid = match output_shape {
        SigningOutputShape::Rsa { modulus_len } => signature.len() == modulus_len,
        // RustCrypto's curve-specific `from_der` enforces exact DER structure
        // and rejects either scalar unless it is in the range 1..n.
        SigningOutputShape::EcdsaP256 => p256::ecdsa::Signature::from_der(signature).is_ok(),
        SigningOutputShape::EcdsaP384 => p384::ecdsa::Signature::from_der(signature).is_ok(),
    };
    if !valid {
        return Err(Ikev2CryptoModuleError::invalid_output());
    }
    Ok(())
}

const fn algorithm_unsupported() -> Ikev2CryptoModuleError {
    Ikev2CryptoModuleError::new(Ikev2CryptoModuleErrorCode::AlgorithmUnsupported)
}

const fn algorithm_not_admitted() -> Ikev2CryptoModuleError {
    Ikev2CryptoModuleError::new(Ikev2CryptoModuleErrorCode::AlgorithmNotAdmitted)
}

#[derive(Debug, Clone, Copy)]
enum MappedEncryption {
    Aead(IkeAeadAlgorithm),
    Cbc(IkeCbcAlgorithm),
}

const fn map_prf(algorithm: Ikev2PrfAlgorithm) -> IkePrfAlgorithm {
    match algorithm {
        Ikev2PrfAlgorithm::HmacSha2_256 => IkePrfAlgorithm::HmacSha2_256,
        Ikev2PrfAlgorithm::HmacSha2_384 => IkePrfAlgorithm::HmacSha2_384,
        Ikev2PrfAlgorithm::HmacSha2_512 => IkePrfAlgorithm::HmacSha2_512,
    }
}

const fn map_integrity(algorithm: Ikev2IntegrityAlgorithm) -> IkeIntegrityAlgorithm {
    match algorithm {
        Ikev2IntegrityAlgorithm::HmacSha2_256_128 => IkeIntegrityAlgorithm::HmacSha2_256_128,
        Ikev2IntegrityAlgorithm::HmacSha2_384_192 => IkeIntegrityAlgorithm::HmacSha2_384_192,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256 => IkeIntegrityAlgorithm::HmacSha2_512_256,
    }
}

const fn map_encryption(algorithm: Ikev2EncryptionAlgorithm) -> Option<MappedEncryption> {
    match algorithm {
        Ikev2EncryptionAlgorithm::AesCbc128 => {
            Some(MappedEncryption::Cbc(IkeCbcAlgorithm::AesCbc128))
        }
        Ikev2EncryptionAlgorithm::AesCbc192 => {
            Some(MappedEncryption::Cbc(IkeCbcAlgorithm::AesCbc192))
        }
        Ikev2EncryptionAlgorithm::AesCbc256 => {
            Some(MappedEncryption::Cbc(IkeCbcAlgorithm::AesCbc256))
        }
        Ikev2EncryptionAlgorithm::AesGcm16_128 => {
            Some(MappedEncryption::Aead(IkeAeadAlgorithm::AesGcm16_128))
        }
        Ikev2EncryptionAlgorithm::AesGcm16_192 => {
            Some(MappedEncryption::Aead(IkeAeadAlgorithm::AesGcm16_192))
        }
        Ikev2EncryptionAlgorithm::AesGcm16_256 => {
            Some(MappedEncryption::Aead(IkeAeadAlgorithm::AesGcm16_256))
        }
        Ikev2EncryptionAlgorithm::Null => None,
    }
}

const fn map_dh_group(group: Ikev2DhGroup) -> IkeDhGroup {
    match group {
        Ikev2DhGroup::Modp2048 => IkeDhGroup::Modp2048,
        Ikev2DhGroup::Ecp256 => IkeDhGroup::Ecp256,
        Ikev2DhGroup::Ecp384 => IkeDhGroup::Ecp384,
        Ikev2DhGroup::Ecp521 => IkeDhGroup::Ecp521,
    }
}
