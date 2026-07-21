//! Opaque proof that an installed ESP SA belongs to an outbound allow policy.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::model::sa_uses_esn;
use crate::namespace::{NamespaceBoundLinuxXfrmBackend, NetworkNamespaceBinding};
use crate::{
    IpAddress, LifetimeConfig, PolicyParameters, SaParameters, UdpEncap, XfrmAction,
    XfrmCompositeInstallRequest, XfrmDirection, XfrmError, XfrmId, XfrmInstallCommitError,
    XfrmMark, XfrmMode, XfrmRequestId, XfrmSelector, XfrmStagedInstallRunError, XfrmTemplate,
};

const IPPROTO_ESP: u8 = 50;

/// Stable, key-free correlation ID for one exact outbound SA/policy identity.
///
/// This ID is safe to persist with a durable re-pin request, but it is never
/// authority: [`InstalledOutboundSaBinding`] must still be presented and
/// freshly validated through its namespace-bound actor. `from_bytes` exists so
/// persisted plans can decode the correlation value; constructing or matching
/// an ID alone cannot mint a binding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutboundSaBindingId([u8; 32]);

impl OutboundSaBindingId {
    /// Decode a persisted correlation value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Encode this correlation value for durable storage.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for OutboundSaBindingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutboundSaBindingId(<redacted>)")
    }
}

/// Opaque authority that one exact ESP SA was installed with a matching
/// outbound allow policy in one namespace-bound Linux XFRM actor.
///
/// The binding has no public constructor and exposes none of its namespace,
/// address, SPI, selector, or policy fingerprint material. It can be issued by
/// [`crate::XfrmStagedInstall::run_and_commit_outbound_sa_policy`] after a
/// fully acknowledged affine install, or recovered by
/// [`NamespaceBoundLinuxXfrmBackend::recover_installed_outbound_sa_binding`]
/// after authoritative kernel readback.
///
/// ```compile_fail
/// let _forged = opc_ipsec_xfrm::InstalledOutboundSaBinding {};
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct InstalledOutboundSaBinding {
    namespace: NetworkNamespaceBinding,
    expectation: OutboundSaPolicyExpectation,
}

impl InstalledOutboundSaBinding {
    pub(crate) const fn new(
        namespace: NetworkNamespaceBinding,
        expectation: OutboundSaPolicyExpectation,
    ) -> Self {
        Self {
            namespace,
            expectation,
        }
    }

    /// Return the stable key-free ID that a durable re-pin request must retain
    /// and later correlate with this live opaque authority.
    #[must_use]
    pub fn id(&self) -> OutboundSaBindingId {
        self.expectation.id()
    }

    pub(crate) fn validated_expectation(
        &self,
        backend: &NamespaceBoundLinuxXfrmBackend,
        parameters: &SaParameters,
        expected_id: OutboundSaBindingId,
    ) -> Result<OutboundSaPolicyExpectation, OutboundSaBindingError> {
        self.validated_expectation_for_actor(
            backend.network_namespace_binding(),
            parameters,
            expected_id,
        )
    }

    pub(crate) fn validated_expectation_for_actor(
        &self,
        actor_namespace: NetworkNamespaceBinding,
        parameters: &SaParameters,
        expected_id: OutboundSaBindingId,
    ) -> Result<OutboundSaPolicyExpectation, OutboundSaBindingError> {
        if self.namespace != actor_namespace {
            return Err(OutboundSaBindingError::rejected(
                "xfrm_outbound_sa_binding_namespace_mismatch",
            ));
        }
        if self.id() != expected_id {
            return Err(OutboundSaBindingError::rejected(
                "xfrm_outbound_sa_binding_id_mismatch",
            ));
        }
        if self.expectation.fingerprint.sa != fingerprint_sa(parameters) {
            return Err(OutboundSaBindingError::rejected(
                "xfrm_outbound_sa_binding_sa_identity_mismatch",
            ));
        }
        Ok(self.expectation.clone())
    }

    /// Revalidate the exact namespace actor, outbound-SA identity, and current
    /// kernel policy immediately before a counter authority uses this binding.
    ///
    /// This stays crate-private so only the SDK counter authority can consume
    /// the capability. Product code cannot use a boolean comparison as a
    /// substitute for the opaque binding.
    pub(crate) async fn validate_current(
        &self,
        backend: &NamespaceBoundLinuxXfrmBackend,
        parameters: &SaParameters,
        expected_id: OutboundSaBindingId,
    ) -> Result<(), OutboundSaBindingError> {
        let expectation = self.validated_expectation(backend, parameters, expected_id)?;
        backend
            .validate_current_outbound_sa_binding(expectation, parameters.clone())
            .await
    }

    #[cfg(test)]
    pub(crate) const fn namespace(&self) -> NetworkNamespaceBinding {
        self.namespace
    }
}

impl fmt::Debug for InstalledOutboundSaBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstalledOutboundSaBinding")
            .field("network_namespace", &"<bound>")
            .field("sa_policy", &"<bound>")
            .finish_non_exhaustive()
    }
}

/// Redaction-safe failure while issuing or recovering an outbound-SA binding.
#[non_exhaustive]
#[derive(Clone)]
pub enum OutboundSaBindingError {
    /// The requested SA/policy pair is not an unambiguous outbound ESP allow
    /// path.
    InvalidRequest {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
    /// The supervised staged install did not complete successfully.
    Install {
        /// Redaction-safe staged-install error.
        source: XfrmStagedInstallRunError,
    },
    /// The acknowledged install could not be committed.
    Commit {
        /// Redaction-safe journal commit error.
        source: XfrmInstallCommitError,
    },
    /// An authoritative Linux readback failed.
    Readback {
        /// Redaction-safe backend error.
        source: XfrmError,
    },
    /// Kernel state did not exactly match the expected outbound pair.
    ReadbackRejected {
        /// Stable payload-free diagnostic code.
        code: &'static str,
    },
}

impl OutboundSaBindingError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest { code } | Self::ReadbackRejected { code } => code,
            Self::Install { source } => source.as_str(),
            Self::Commit { source } => source.as_str(),
            Self::Readback { .. } => "xfrm_outbound_sa_binding_readback_failed",
        }
    }

    pub(crate) const fn invalid(code: &'static str) -> Self {
        Self::InvalidRequest { code }
    }

    pub(crate) const fn rejected(code: &'static str) -> Self {
        Self::ReadbackRejected { code }
    }
}

impl fmt::Debug for OutboundSaBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundSaBindingError")
            .field("code", &self.code())
            .finish()
    }
}

impl fmt::Display for OutboundSaBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl Error for OutboundSaBindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Install { source } => Some(source),
            Self::Commit { source } => Some(source),
            Self::Readback { source } => Some(source),
            Self::InvalidRequest { .. } | Self::ReadbackRejected { .. } => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutboundSaPolicyFingerprint {
    sa: [u8; 32],
    policy: [u8; 32],
}

/// Exact non-secret fields retained by an opaque binding.
///
/// Algorithm keys and replay counters are deliberately removed. The latter
/// change during counter restoration; direction authority instead binds the
/// stable SA identity/configuration and exact outbound policy.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OutboundSaPolicyExpectation {
    sa: SaParameters,
    policy: PolicyParameters,
    replay_esn: bool,
    crypto: OutboundSaCryptoExpectation,
    fingerprint: OutboundSaPolicyFingerprint,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OutboundSaCryptoExpectation {
    pub(crate) auth: Option<OutboundSaAuthExpectation>,
    pub(crate) crypt: Option<OutboundSaAlgorithmExpectation>,
    pub(crate) aead: Option<OutboundSaAeadExpectation>,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OutboundSaAlgorithmExpectation {
    pub(crate) name: String,
    pub(crate) key_len: usize,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OutboundSaAuthExpectation {
    pub(crate) algorithm: OutboundSaAlgorithmExpectation,
    pub(crate) truncation_len_bits: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OutboundSaAeadExpectation {
    pub(crate) algorithm: OutboundSaAlgorithmExpectation,
    pub(crate) icv_len_bits: u32,
}

impl fmt::Debug for OutboundSaPolicyExpectation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutboundSaPolicyExpectation(<redacted>)")
    }
}

impl OutboundSaPolicyExpectation {
    pub(crate) fn id(&self) -> OutboundSaBindingId {
        let mut digest = Sha256::new();
        digest.update(b"opc-xfrm-outbound-sa-policy-binding-id-v1\0");
        digest.update(self.fingerprint.sa);
        digest.update(self.fingerprint.policy);
        OutboundSaBindingId(digest.finalize().into())
    }

    pub(crate) const fn replay_esn(&self) -> bool {
        self.replay_esn
    }

    pub(crate) const fn crypto(&self) -> &OutboundSaCryptoExpectation {
        &self.crypto
    }
}

impl fmt::Debug for OutboundSaPolicyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OutboundSaPolicyFingerprint(<redacted>)")
    }
}

pub(crate) fn validate_outbound_request(
    request: &XfrmCompositeInstallRequest,
) -> Result<OutboundSaPolicyExpectation, OutboundSaBindingError> {
    let sa = &request.sa.parameters;
    let policy = &request.policy.parameters;

    if sa.id.protocol != IPPROTO_ESP || sa.id.spi == 0 {
        return Err(OutboundSaBindingError::invalid(
            "xfrm_outbound_sa_binding_not_esp",
        ));
    }
    if policy.direction != XfrmDirection::Out {
        return Err(OutboundSaBindingError::invalid(
            "xfrm_outbound_sa_binding_policy_not_outbound",
        ));
    }
    if policy.action != XfrmAction::Allow {
        return Err(OutboundSaBindingError::invalid(
            "xfrm_outbound_sa_binding_policy_not_allow",
        ));
    }
    if policy.selector != sa.selector {
        return Err(OutboundSaBindingError::invalid(
            "xfrm_outbound_sa_binding_selector_mismatch",
        ));
    }
    if policy.mark != sa.mark {
        return Err(OutboundSaBindingError::invalid(
            "xfrm_outbound_sa_binding_mark_mismatch",
        ));
    }
    if policy.if_id != sa.if_id {
        return Err(OutboundSaBindingError::invalid(
            "xfrm_outbound_sa_binding_if_id_mismatch",
        ));
    }
    let [template] = policy.templates.as_slice() else {
        return Err(OutboundSaBindingError::invalid(
            "xfrm_outbound_sa_binding_template_cardinality",
        ));
    };
    if !template_matches_sa(template, sa) {
        return Err(OutboundSaBindingError::invalid(
            "xfrm_outbound_sa_binding_template_mismatch",
        ));
    }

    let fingerprint = OutboundSaPolicyFingerprint {
        sa: fingerprint_sa(sa),
        policy: fingerprint_policy(policy),
    };
    let replay_esn = sa_uses_esn(sa);
    let crypto = OutboundSaCryptoExpectation {
        auth: sa
            .auth
            .as_ref()
            .map(|(algorithm, key)| OutboundSaAuthExpectation {
                algorithm: OutboundSaAlgorithmExpectation {
                    name: algorithm.name.clone(),
                    key_len: key.len(),
                },
                truncation_len_bits: algorithm.truncation_len_bits,
            }),
        crypt: sa
            .crypt
            .as_ref()
            .map(|(algorithm, key)| OutboundSaAlgorithmExpectation {
                name: algorithm.name.clone(),
                key_len: key.len(),
            }),
        aead: sa
            .aead
            .as_ref()
            .map(|(algorithm, key)| OutboundSaAeadExpectation {
                algorithm: OutboundSaAlgorithmExpectation {
                    name: algorithm.name.clone(),
                    key_len: key.len(),
                },
                icv_len_bits: algorithm.icv_len_bits,
            }),
    };
    let mut retained_sa = sa.clone();
    retained_sa.auth = None;
    retained_sa.crypt = None;
    retained_sa.aead = None;
    retained_sa.replay_state = None;
    Ok(OutboundSaPolicyExpectation {
        sa: retained_sa,
        policy: policy.clone(),
        replay_esn,
        crypto,
        fingerprint,
    })
}

pub(crate) fn readback_mismatch<T>(code: &'static str) -> Result<T, OutboundSaBindingError> {
    Err(OutboundSaBindingError::rejected(code))
}

pub(crate) fn expected_sa(expectation: &OutboundSaPolicyExpectation) -> &SaParameters {
    &expectation.sa
}

pub(crate) fn expected_policy(expectation: &OutboundSaPolicyExpectation) -> &PolicyParameters {
    &expectation.policy
}

fn template_matches_sa(template: &XfrmTemplate, sa: &SaParameters) -> bool {
    let spi_matches = template.id.spi == sa.id.spi
        || (template.id.spi == 0
            && sa.request_id.is_some()
            && template.request_id == sa.request_id);
    spi_matches
        && template.id.destination == sa.id.destination
        && template.id.protocol == IPPROTO_ESP
        && template.source_address == sa.source_address
        && template.request_id == sa.request_id
        && template.mode == sa.mode
}

fn fingerprint_sa(parameters: &SaParameters) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"opc-xfrm-outbound-sa-binding-v1\0");
    hash_selector(&mut digest, &parameters.selector);
    hash_id(&mut digest, parameters.id);
    hash_address(&mut digest, parameters.source_address);
    hash_request_id(&mut digest, parameters.request_id);
    hash_mode(&mut digest, parameters.mode);
    hash_lifetime(&mut digest, parameters.lifetime);
    digest.update(parameters.replay_window.to_be_bytes());
    digest.update([sa_uses_esn(parameters) as u8]);
    hash_encap(&mut digest, parameters.encap);
    hash_mark(&mut digest, parameters.mark);
    hash_mark(&mut digest, parameters.output_mark);
    hash_optional_u32(&mut digest, parameters.if_id);
    match parameters.egress_dscp {
        Some(dscp) => {
            digest.update([1, dscp.get()]);
        }
        None => digest.update([0]),
    }
    match &parameters.auth {
        Some((algorithm, key)) => {
            digest.update([1]);
            hash_bytes(&mut digest, algorithm.name.as_bytes());
            digest.update(algorithm.truncation_len_bits.to_be_bytes());
            digest.update((key.len() as u64).to_be_bytes());
        }
        None => digest.update([0]),
    }
    match &parameters.crypt {
        Some((algorithm, key)) => {
            digest.update([1]);
            hash_bytes(&mut digest, algorithm.name.as_bytes());
            digest.update((key.len() as u64).to_be_bytes());
        }
        None => digest.update([0]),
    }
    match &parameters.aead {
        Some((algorithm, key)) => {
            digest.update([1]);
            hash_bytes(&mut digest, algorithm.name.as_bytes());
            digest.update(algorithm.icv_len_bits.to_be_bytes());
            digest.update((key.len() as u64).to_be_bytes());
        }
        None => digest.update([0]),
    }
    digest.finalize().into()
}

fn hash_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn fingerprint_policy(parameters: &PolicyParameters) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"opc-xfrm-outbound-policy-binding-v1\0");
    hash_selector(&mut digest, &parameters.selector);
    hash_direction(&mut digest, parameters.direction);
    hash_action(&mut digest, parameters.action);
    digest.update(parameters.priority.to_be_bytes());
    digest.update((parameters.templates.len() as u64).to_be_bytes());
    for template in &parameters.templates {
        hash_template(&mut digest, template);
    }
    hash_mark(&mut digest, parameters.mark);
    hash_optional_u32(&mut digest, parameters.if_id);
    digest.finalize().into()
}

fn hash_selector(digest: &mut Sha256, selector: &XfrmSelector) {
    hash_address(digest, selector.source);
    hash_address(digest, selector.destination);
    digest.update(selector.source_port.to_be_bytes());
    digest.update(selector.destination_port.to_be_bytes());
    digest.update([
        selector.protocol,
        selector.source_prefix_len,
        selector.destination_prefix_len,
    ]);
}

fn hash_id(digest: &mut Sha256, id: XfrmId) {
    hash_address(digest, id.destination);
    digest.update(id.spi.to_be_bytes());
    digest.update([id.protocol]);
}

fn hash_address(digest: &mut Sha256, address: IpAddress) {
    match address {
        IpAddress::Ipv4(octets) => {
            digest.update([4]);
            digest.update(octets);
        }
        IpAddress::Ipv6(octets) => {
            digest.update([6]);
            digest.update(octets);
        }
    }
}

fn hash_request_id(digest: &mut Sha256, request_id: Option<XfrmRequestId>) {
    hash_optional_u32(digest, request_id.map(XfrmRequestId::get));
}

fn hash_mode(digest: &mut Sha256, mode: XfrmMode) {
    digest.update([match mode {
        XfrmMode::Transport => 0,
        XfrmMode::Tunnel => 1,
        XfrmMode::Beet => 4,
    }]);
}

fn hash_direction(digest: &mut Sha256, direction: XfrmDirection) {
    digest.update([match direction {
        XfrmDirection::In => 0,
        XfrmDirection::Out => 1,
        XfrmDirection::Forward => 2,
    }]);
}

fn hash_action(digest: &mut Sha256, action: XfrmAction) {
    digest.update([match action {
        XfrmAction::Allow => 0,
        XfrmAction::Block => 1,
    }]);
}

fn hash_mark(digest: &mut Sha256, mark: Option<XfrmMark>) {
    match mark {
        Some(mark) => {
            digest.update([1]);
            digest.update(mark.value.to_be_bytes());
            digest.update(mark.mask.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn hash_optional_u32(digest: &mut Sha256, value: Option<u32>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn hash_lifetime(digest: &mut Sha256, lifetime: LifetimeConfig) {
    for value in [
        lifetime.soft_byte_limit,
        lifetime.hard_byte_limit,
        lifetime.soft_packet_limit,
        lifetime.hard_packet_limit,
        lifetime.soft_add_expires_seconds,
        lifetime.hard_add_expires_seconds,
    ] {
        digest.update(value.to_be_bytes());
    }
}

fn hash_encap(digest: &mut Sha256, encap: Option<UdpEncap>) {
    match encap {
        Some(encap) => {
            digest.update([1]);
            digest.update(encap.encap_type.to_be_bytes());
            digest.update(encap.source_port.to_be_bytes());
            digest.update(encap.destination_port.to_be_bytes());
        }
        None => digest.update([0]),
    }
}

fn hash_template(digest: &mut Sha256, template: &XfrmTemplate) {
    hash_id(digest, template.id);
    hash_address(digest, template.source_address);
    hash_request_id(digest, template.request_id);
    hash_mode(digest, template.mode);
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use crate::{
        Algorithm, AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, KeyMaterial,
        XfrmCompositeInstallRequest,
    };

    pub(crate) fn ipv4(octets: [u8; 4]) -> IpAddress {
        IpAddress::Ipv4(octets)
    }

    pub(crate) fn outbound_request() -> XfrmCompositeInstallRequest {
        let selector = XfrmSelector::new(ipv4([10, 0, 0, 1]), ipv4([10, 0, 0, 2]), 17);
        let mark = Some(XfrmMark {
            value: 0x1234_0000,
            mask: 0xffff_0000,
        });
        let request_id = XfrmRequestId::new(77);
        let sa = SaParameters {
            selector: selector.clone(),
            id: XfrmId {
                destination: ipv4([192, 0, 2, 2]),
                spi: 0xdead_beef,
                protocol: IPPROTO_ESP,
            },
            source_address: ipv4([192, 0, 2, 1]),
            request_id,
            auth: Some((
                AuthAlgorithm::hmac_sha256(128),
                KeyMaterial::new(vec![0xa5; 32]),
            )),
            crypt: Some((Algorithm::null(), KeyMaterial::new(Vec::new()))),
            aead: None,
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 64,
            replay_state: None,
            encap: None,
            mark,
            output_mark: None,
            if_id: Some(19),
            egress_dscp: None,
        };
        let policy = PolicyParameters {
            selector,
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: 100,
            templates: vec![XfrmTemplate {
                id: sa.id,
                source_address: sa.source_address,
                request_id,
                mode: sa.mode,
            }],
            mark,
            if_id: Some(19),
        };
        XfrmCompositeInstallRequest {
            sa: InstallSaRequest { parameters: sa },
            policy: InstallPolicyRequest { parameters: policy },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{ipv4, outbound_request};
    use super::*;
    use crate::{AuthAlgorithm, KeyMaterial};

    #[test]
    fn exact_outbound_pair_is_accepted() {
        assert!(validate_outbound_request(&outbound_request()).is_ok());
    }

    #[test]
    fn inbound_block_and_structural_mismatches_fail_closed() {
        let mut inbound = outbound_request();
        inbound.policy.parameters.direction = XfrmDirection::In;
        assert_eq!(
            validate_outbound_request(&inbound).unwrap_err().code(),
            "xfrm_outbound_sa_binding_policy_not_outbound"
        );

        let mut block = outbound_request();
        block.policy.parameters.action = XfrmAction::Block;
        assert_eq!(
            validate_outbound_request(&block).unwrap_err().code(),
            "xfrm_outbound_sa_binding_policy_not_allow"
        );

        let mut selector = outbound_request();
        selector.policy.parameters.selector.protocol = 6;
        assert_eq!(
            validate_outbound_request(&selector).unwrap_err().code(),
            "xfrm_outbound_sa_binding_selector_mismatch"
        );

        let mut mark = outbound_request();
        mark.policy.parameters.mark = None;
        assert_eq!(
            validate_outbound_request(&mark).unwrap_err().code(),
            "xfrm_outbound_sa_binding_mark_mismatch"
        );

        let mut if_id = outbound_request();
        if_id.policy.parameters.if_id = Some(20);
        assert_eq!(
            validate_outbound_request(&if_id).unwrap_err().code(),
            "xfrm_outbound_sa_binding_if_id_mismatch"
        );

        let mut duplicate = outbound_request();
        duplicate
            .policy
            .parameters
            .templates
            .push(duplicate.policy.parameters.templates[0]);
        assert_eq!(
            validate_outbound_request(&duplicate).unwrap_err().code(),
            "xfrm_outbound_sa_binding_template_cardinality"
        );

        let mut template = outbound_request();
        template.policy.parameters.templates[0].source_address = IpAddress::Ipv4([203, 0, 113, 9]);
        assert_eq!(
            validate_outbound_request(&template).unwrap_err().code(),
            "xfrm_outbound_sa_binding_template_mismatch"
        );

        let mut wildcard_without_reqid = outbound_request();
        wildcard_without_reqid.sa.parameters.request_id = None;
        wildcard_without_reqid.policy.parameters.templates[0].request_id = None;
        wildcard_without_reqid.policy.parameters.templates[0].id.spi = 0;
        assert_eq!(
            validate_outbound_request(&wildcard_without_reqid)
                .unwrap_err()
                .code(),
            "xfrm_outbound_sa_binding_template_mismatch"
        );

        let mut mismatched_reqid = outbound_request();
        mismatched_reqid.policy.parameters.templates[0].id.spi = 0;
        mismatched_reqid.policy.parameters.templates[0].request_id = XfrmRequestId::new(78);
        assert_eq!(
            validate_outbound_request(&mismatched_reqid)
                .unwrap_err()
                .code(),
            "xfrm_outbound_sa_binding_template_mismatch"
        );
    }

    #[test]
    fn matching_nonzero_reqid_safely_binds_wildcard_template_spi() {
        let mut request = outbound_request();
        request.policy.parameters.templates[0].id.spi = 0;
        assert!(validate_outbound_request(&request).is_ok());
    }

    #[test]
    fn fingerprint_ignores_key_bytes_and_mutable_replay_counters_but_not_crypto_shape() {
        let request = outbound_request();
        let expected = validate_outbound_request(&request).unwrap();

        let mut changed_runtime = request.clone();
        changed_runtime.sa.parameters.auth.as_mut().unwrap().1 = KeyMaterial::new(vec![0x5a; 32]);
        changed_runtime.sa.parameters.replay_state = Some(crate::SaReplayState::fresh(64));
        assert_eq!(
            expected.fingerprint.sa,
            fingerprint_sa(&changed_runtime.sa.parameters)
        );

        let mut changed_crypto = request.clone();
        changed_crypto.sa.parameters.auth.as_mut().unwrap().0 = AuthAlgorithm::hmac_sha512(256);
        assert_ne!(
            expected.fingerprint.sa,
            fingerprint_sa(&changed_crypto.sa.parameters)
        );

        let mut changed_identity = request;
        changed_identity.sa.parameters.id.spi = 0xfeed_face;
        assert_ne!(
            expected.fingerprint.sa,
            fingerprint_sa(&changed_identity.sa.parameters)
        );
    }

    #[test]
    fn wide_window_explicit_false_snapshot_uses_canonical_esn_binding_identity() {
        let base = outbound_request();
        let base_expectation = validate_outbound_request(&base).unwrap();
        assert!(base_expectation.replay_esn());

        let mut explicit_false = base.clone();
        let mut replay_state = crate::SaReplayState::fresh(64);
        replay_state.esn = false;
        explicit_false.sa.parameters.replay_state = Some(replay_state);
        let explicit_expectation = validate_outbound_request(&explicit_false).unwrap();
        assert!(explicit_expectation.replay_esn());
        assert_eq!(explicit_expectation.id(), base_expectation.id());
    }

    #[test]
    fn debug_and_errors_do_not_expose_hostile_identity_material() {
        let expectation = validate_outbound_request(&outbound_request()).unwrap();
        let binding = InstalledOutboundSaBinding::new(
            NetworkNamespaceBinding::for_test(1_234_567_890, 9_876_543_210),
            expectation,
        );
        let debug = format!("{binding:?}");
        for marker in ["3735928559", "1234567890", "9876543210", "192.0.2"] {
            assert!(!debug.contains(marker));
        }
        assert_eq!(
            format!("{:?}", binding.id()),
            "OutboundSaBindingId(<redacted>)"
        );
        let error = OutboundSaBindingError::rejected("xfrm_outbound_sa_binding_test");
        assert_eq!(
            format!("{error:?}"),
            "OutboundSaBindingError { code: \"xfrm_outbound_sa_binding_test\" }"
        );
    }

    #[test]
    fn stable_id_correlates_restart_and_separates_same_spi_substitutions() {
        let base = outbound_request();
        let id = validate_outbound_request(&base).unwrap().id();
        assert_eq!(OutboundSaBindingId::from_bytes(id.to_bytes()), id);
        assert_eq!(validate_outbound_request(&base.clone()).unwrap().id(), id);

        let mut destination = base.clone();
        let replacement = ipv4([198, 51, 100, 44]);
        destination.sa.parameters.id.destination = replacement;
        destination.policy.parameters.templates[0].id.destination = replacement;
        assert_ne!(validate_outbound_request(&destination).unwrap().id(), id);

        let mut mark = base.clone();
        let replacement = Some(XfrmMark {
            value: 0x4321_0000,
            mask: 0xffff_0000,
        });
        mark.sa.parameters.mark = replacement;
        mark.policy.parameters.mark = replacement;
        assert_ne!(validate_outbound_request(&mark).unwrap().id(), id);

        let mut if_id = base.clone();
        if_id.sa.parameters.if_id = Some(20);
        if_id.policy.parameters.if_id = Some(20);
        assert_ne!(validate_outbound_request(&if_id).unwrap().id(), id);
    }

    #[test]
    fn same_dscp_with_different_generic_output_mark_has_different_id() {
        let mut first = outbound_request();
        first.sa.parameters.egress_dscp = Some(crate::DscpCodepoint::new(46).unwrap());
        first.sa.parameters.output_mark = Some(XfrmMark {
            value: 0x0001_0000,
            mask: 0x00ff_0000,
        });
        let mut second = first.clone();
        second.sa.parameters.output_mark = Some(XfrmMark {
            value: 0x0002_0000,
            mask: 0x00ff_0000,
        });

        assert_ne!(
            validate_outbound_request(&first).unwrap().id(),
            validate_outbound_request(&second).unwrap().id()
        );
    }
}
