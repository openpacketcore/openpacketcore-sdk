//! IKEv2 Child SA to XFRM request mapping.
//!
//! This module converts product-neutral Child SA negotiation intent from
//! `opc-proto-ikev2` into explicit XFRM SA and policy install requests. It does
//! not negotiate IKE, allocate SPIs, or choose subscriber policy. The optional
//! KEYMAT helper derives caller-supplied Child SA profiles into the same
//! directional key type consumed by the mapper.

use std::{error::Error, fmt};

use opc_proto_ikev2::{
    derive_child_sa_key_material, Ikev2ChildSaCryptoProfile, Ikev2ChildSaNegotiation,
    Ikev2EncryptionAlgorithm, Ikev2IntegrityAlgorithm, Ikev2SaInitCryptoError,
    Ikev2SaInitCryptoErrorCode, Ikev2TrafficSelectorBuild, IKEV2_TS_IPV4_ADDR_RANGE,
    IKEV2_TS_IPV6_ADDR_RANGE,
};

use crate::{
    AeadAlgorithm, Algorithm, AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, IpAddress,
    KeyMaterial, LifetimeConfig, PolicyParameters, SaParameters, XfrmAction,
    XfrmCompositeInstallRequest, XfrmDirection, XfrmId, XfrmMode, XfrmRequestId, XfrmSelector,
    XfrmTemplate,
};

/// IKEv2 Security Protocol ID for ESP proposals.
pub const IKEV2_SECURITY_PROTOCOL_ID_ESP: u8 = 3;

/// IP protocol number for ESP in Linux XFRM identities.
pub const IPPROTO_ESP: u8 = 50;

/// Directional key material used when installing one Child SA direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaXfrmKeys {
    /// Authentication algorithm and key, when the selected transform uses a
    /// separate integrity algorithm.
    pub auth: Option<(AuthAlgorithm, KeyMaterial)>,
    /// Encryption or AEAD algorithm and key.
    pub crypt: Option<(Algorithm, KeyMaterial)>,
    /// Combined-mode AEAD algorithm and key.
    pub aead: Option<(AeadAlgorithm, KeyMaterial)>,
}

impl Ikev2ChildSaXfrmKeys {
    /// Create directional XFRM key material.
    pub fn new(
        auth: Option<(AuthAlgorithm, KeyMaterial)>,
        crypt: Option<(Algorithm, KeyMaterial)>,
    ) -> Self {
        Self {
            auth,
            crypt,
            aead: None,
        }
    }

    /// Create directional XFRM key material for a combined-mode AEAD SA.
    pub fn aead(aead: (AeadAlgorithm, KeyMaterial)) -> Self {
        Self {
            auth: None,
            crypt: None,
            aead: Some(aead),
        }
    }

    /// Return true when no authentication or encryption key material is present.
    pub fn is_empty(&self) -> bool {
        self.auth.is_none() && self.crypt.is_none() && self.aead.is_none()
    }
}

/// Inputs required to map one negotiated IKEv2 Child SA into XFRM installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaXfrmRequest {
    /// Negotiated Child SA intent from `opc-proto-ikev2`.
    pub negotiation: Ikev2ChildSaNegotiation,
    /// Local outer tunnel endpoint.
    pub local_tunnel_address: IpAddress,
    /// Remote outer tunnel endpoint.
    pub remote_tunnel_address: IpAddress,
    /// Local responder SPI allocated for the inbound SA.
    pub responder_spi: u32,
    /// Inbound SA key material.
    pub inbound: Ikev2ChildSaXfrmKeys,
    /// Outbound SA key material.
    pub outbound: Ikev2ChildSaXfrmKeys,
    /// XFRM mode to install.
    pub mode: XfrmMode,
    /// Lifetime limits to apply to both SAs.
    pub lifetime: LifetimeConfig,
    /// Replay window to apply to both SAs.
    pub replay_window: u8,
    /// Policy priority to apply to both policies.
    pub policy_priority: u32,
}

/// XFRM install requests produced for a bidirectional Child SA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaXfrmRequests {
    /// Inbound SA install request, keyed by the responder SPI.
    pub inbound_sa: InstallSaRequest,
    /// Outbound SA install request, keyed by the initiator SPI.
    pub outbound_sa: InstallSaRequest,
    /// Inbound policy install request.
    pub inbound_policy: InstallPolicyRequest,
    /// Outbound policy install request.
    pub outbound_policy: InstallPolicyRequest,
}

/// Directional XFRM key material derived from Child SA KEYMAT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ikev2ChildSaDirectionalXfrmKeys {
    /// Inbound SA keys at the responder, using initiator-to-responder KEYMAT.
    pub inbound: Ikev2ChildSaXfrmKeys,
    /// Outbound SA keys at the responder, using responder-to-initiator KEYMAT.
    pub outbound: Ikev2ChildSaXfrmKeys,
}

impl Ikev2ChildSaXfrmRequests {
    /// Return SA+policy composite install requests in inbound, outbound order.
    pub fn composite_installs(&self) -> [XfrmCompositeInstallRequest; 2] {
        [
            XfrmCompositeInstallRequest {
                sa: self.inbound_sa.clone(),
                policy: self.inbound_policy.clone(),
            },
            XfrmCompositeInstallRequest {
                sa: self.outbound_sa.clone(),
                policy: self.outbound_policy.clone(),
            },
        ]
    }
}

/// Error returned while deriving Child SA KEYMAT into XFRM key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ikev2ChildSaKeyMaterialError {
    /// Lower-level IKEv2 KEYMAT derivation failed.
    KeyDerivation(Ikev2SaInitCryptoErrorCode),
    /// The negotiated crypto profile has no SDK XFRM algorithm mapping.
    UnsupportedAlgorithmMapping,
}

impl Ikev2ChildSaKeyMaterialError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::KeyDerivation(_) => "ikev2_child_sa_keymat_derivation_failed",
            Self::UnsupportedAlgorithmMapping => {
                "ikev2_child_sa_keymat_unsupported_algorithm_mapping"
            }
        }
    }
}

impl From<Ikev2SaInitCryptoError> for Ikev2ChildSaKeyMaterialError {
    fn from(source: Ikev2SaInitCryptoError) -> Self {
        Self::KeyDerivation(source.code())
    }
}

impl fmt::Display for Ikev2ChildSaKeyMaterialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2ChildSaKeyMaterialError {}

/// Validation failure while mapping a negotiated Child SA into XFRM requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ikev2ChildSaXfrmError {
    /// The selected Child SA protocol is not ESP.
    UnsupportedProtocolId {
        /// Selected IKEv2 protocol ID.
        protocol_id: u8,
    },
    /// The initiator SPI is not exactly 32 bits.
    InitiatorSpiInvalidLength {
        /// Observed SPI length in octets.
        len: usize,
    },
    /// The initiator SPI is zero.
    InitiatorSpiZero,
    /// The responder SPI is zero.
    ResponderSpiZero,
    /// Inbound key material is missing.
    MissingInboundKeyMaterial,
    /// Outbound key material is missing.
    MissingOutboundKeyMaterial,
    /// The replay window is zero.
    ReplayWindowZero,
    /// The traffic selector type is not IPv4 or IPv6 address range.
    TrafficSelectorAddressTypeUnsupported {
        /// Traffic selector type.
        ts_type: u8,
    },
    /// The traffic selector address length is invalid for its type.
    TrafficSelectorAddressLengthInvalid {
        /// Traffic selector type.
        ts_type: u8,
        /// Address length in octets.
        len: usize,
    },
    /// The traffic selector address range is not expressible as a single prefix.
    TrafficSelectorAddressRangeUnsupported,
    /// The traffic selector port range cannot be represented by this XFRM model.
    TrafficSelectorPortRangeUnsupported {
        /// Start port.
        start: u16,
        /// End port.
        end: u16,
    },
    /// Initiator and responder selectors disagree on the inner IP protocol.
    TrafficSelectorProtocolMismatch {
        /// Initiator-side selector protocol.
        initiator: u8,
        /// Responder-side selector protocol.
        responder: u8,
    },
    /// Initiator and responder selector address families differ.
    TrafficSelectorAddressFamilyMismatch,
    /// Local and remote tunnel endpoint address families differ.
    TunnelEndpointAddressFamilyMismatch,
}

impl Ikev2ChildSaXfrmError {
    /// Stable machine-readable error code.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UnsupportedProtocolId { .. } => "ikev2_child_sa_xfrm_unsupported_protocol_id",
            Self::InitiatorSpiInvalidLength { .. } => {
                "ikev2_child_sa_xfrm_initiator_spi_invalid_length"
            }
            Self::InitiatorSpiZero => "ikev2_child_sa_xfrm_initiator_spi_zero",
            Self::ResponderSpiZero => "ikev2_child_sa_xfrm_responder_spi_zero",
            Self::MissingInboundKeyMaterial => "ikev2_child_sa_xfrm_missing_inbound_key_material",
            Self::MissingOutboundKeyMaterial => "ikev2_child_sa_xfrm_missing_outbound_key_material",
            Self::ReplayWindowZero => "ikev2_child_sa_xfrm_replay_window_zero",
            Self::TrafficSelectorAddressTypeUnsupported { .. } => {
                "ikev2_child_sa_xfrm_ts_address_type_unsupported"
            }
            Self::TrafficSelectorAddressLengthInvalid { .. } => {
                "ikev2_child_sa_xfrm_ts_address_length_invalid"
            }
            Self::TrafficSelectorAddressRangeUnsupported => {
                "ikev2_child_sa_xfrm_ts_address_range_unsupported"
            }
            Self::TrafficSelectorPortRangeUnsupported { .. } => {
                "ikev2_child_sa_xfrm_ts_port_range_unsupported"
            }
            Self::TrafficSelectorProtocolMismatch { .. } => {
                "ikev2_child_sa_xfrm_ts_protocol_mismatch"
            }
            Self::TrafficSelectorAddressFamilyMismatch => {
                "ikev2_child_sa_xfrm_ts_address_family_mismatch"
            }
            Self::TunnelEndpointAddressFamilyMismatch => {
                "ikev2_child_sa_xfrm_tunnel_endpoint_address_family_mismatch"
            }
        }
    }
}

impl fmt::Display for Ikev2ChildSaXfrmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error for Ikev2ChildSaXfrmError {}

/// Derive Child SA KEYMAT and map it into bidirectional XFRM key material.
///
/// AES-GCM profiles map to [`Ikev2ChildSaXfrmKeys::aead`] with Linux
/// [`crate::XFRM_AEAD_RFC4106_GCM_AES`] and a 128-bit ICV. AES-CBC profiles with supported
/// HMAC-SHA2 integrity map to separate crypt/auth slots.
///
/// # Errors
///
/// Returns [`Ikev2ChildSaKeyMaterialError`] when KEYMAT derivation fails or the
/// selected profile has no SDK XFRM algorithm-name mapping.
pub fn derive_child_sa_xfrm_keys(
    profile: Ikev2ChildSaCryptoProfile,
    sk_d: &[u8],
    initiator_nonce: &[u8],
    responder_nonce: &[u8],
    new_dh_shared_secret: Option<&[u8]>,
) -> Result<Ikev2ChildSaDirectionalXfrmKeys, Ikev2ChildSaKeyMaterialError> {
    let key_material = derive_child_sa_key_material(
        profile,
        sk_d,
        initiator_nonce,
        responder_nonce,
        new_dh_shared_secret,
    )?;

    let inbound = child_sa_xfrm_keys_from_direction(
        profile,
        key_material.initiator_to_responder_encryption(),
        key_material.initiator_to_responder_integrity(),
    )?;
    let outbound = child_sa_xfrm_keys_from_direction(
        profile,
        key_material.responder_to_initiator_encryption(),
        key_material.responder_to_initiator_integrity(),
    )?;

    Ok(Ikev2ChildSaDirectionalXfrmKeys { inbound, outbound })
}

/// Build bidirectional XFRM SA and policy install requests for a Child SA.
///
/// A traffic selector address range is accepted when it collapses to a single
/// address or spans exactly one aligned CIDR block; the block's prefix length
/// flows into the XFRM selector, so a 3GPP route-all responder selector installs
/// as a `/0` prefix. A range that is not expressible as a single prefix is
/// rejected.
///
/// # Errors
///
/// Returns [`Ikev2ChildSaXfrmError`] when the negotiation uses a protocol,
/// SPI, selector range, endpoint family, or key-material shape that the current
/// SDK XFRM model cannot represent exactly.
pub fn build_xfrm_requests_from_ikev2_child_sa(
    request: &Ikev2ChildSaXfrmRequest,
) -> Result<Ikev2ChildSaXfrmRequests, Ikev2ChildSaXfrmError> {
    build_xfrm_requests_from_ikev2_child_sa_inner(request, None)
}

/// Build Child-SA installs whose policies match a shared XFRM request ID.
///
/// Both SA states carry `request_id`, while their policy templates use a
/// wildcard SPI and the same non-zero request ID. Reusing the request ID for an
/// old and replacement Child SA lets one selector policy admit both SPIs during
/// RFC 7296 make-before-break overlap. The caller owns request-ID allocation and
/// retirement; unrelated live Child SAs must not share one.
///
/// # Errors
///
/// Returns [`Ikev2ChildSaXfrmError`] under the same validation rules as
/// [`build_xfrm_requests_from_ikev2_child_sa`].
pub fn build_xfrm_requests_from_ikev2_child_sa_with_request_id(
    request: &Ikev2ChildSaXfrmRequest,
    request_id: XfrmRequestId,
) -> Result<Ikev2ChildSaXfrmRequests, Ikev2ChildSaXfrmError> {
    build_xfrm_requests_from_ikev2_child_sa_inner(request, Some(request_id))
}

fn build_xfrm_requests_from_ikev2_child_sa_inner(
    request: &Ikev2ChildSaXfrmRequest,
    request_id: Option<XfrmRequestId>,
) -> Result<Ikev2ChildSaXfrmRequests, Ikev2ChildSaXfrmError> {
    validate_request(request)?;

    let initiator_spi = initiator_spi_u32(&request.negotiation.initiator_spi)?;
    let initiator_selector = selector_prefix(&request.negotiation.initiator_traffic_selector)?;
    let responder_selector = selector_prefix(&request.negotiation.responder_traffic_selector)?;
    if !same_address_family(initiator_selector.0, responder_selector.0) {
        return Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressFamilyMismatch);
    }

    let inner_protocol = selector_protocol(
        request
            .negotiation
            .initiator_traffic_selector
            .ip_protocol_id,
        request
            .negotiation
            .responder_traffic_selector
            .ip_protocol_id,
    )?;
    let initiator_port = selector_port(
        request.negotiation.initiator_traffic_selector.start_port,
        request.negotiation.initiator_traffic_selector.end_port,
    )?;
    let responder_port = selector_port(
        request.negotiation.responder_traffic_selector.start_port,
        request.negotiation.responder_traffic_selector.end_port,
    )?;

    let inbound_selector = xfrm_selector(
        initiator_selector,
        responder_selector,
        initiator_port,
        responder_port,
        inner_protocol,
    );
    let outbound_selector = xfrm_selector(
        responder_selector,
        initiator_selector,
        responder_port,
        initiator_port,
        inner_protocol,
    );

    let inbound_id = XfrmId {
        destination: request.local_tunnel_address,
        spi: request.responder_spi,
        protocol: IPPROTO_ESP,
    };
    let outbound_id = XfrmId {
        destination: request.remote_tunnel_address,
        spi: initiator_spi,
        protocol: IPPROTO_ESP,
    };

    let inbound_sa = InstallSaRequest {
        parameters: SaParameters {
            selector: inbound_selector.clone(),
            id: inbound_id,
            source_address: request.remote_tunnel_address,
            request_id,
            auth: request.inbound.auth.clone(),
            crypt: request.inbound.crypt.clone(),
            aead: request.inbound.aead.clone(),
            mode: request.mode,
            lifetime: request.lifetime,
            replay_window: u32::from(request.replay_window),
            replay_state: None,
            encap: None,
            mark: None,
            output_mark: None,
            if_id: None,
            egress_dscp: None,
        },
    };
    let outbound_sa = InstallSaRequest {
        parameters: SaParameters {
            selector: outbound_selector.clone(),
            id: outbound_id,
            source_address: request.local_tunnel_address,
            request_id,
            auth: request.outbound.auth.clone(),
            crypt: request.outbound.crypt.clone(),
            aead: request.outbound.aead.clone(),
            mode: request.mode,
            lifetime: request.lifetime,
            replay_window: u32::from(request.replay_window),
            replay_state: None,
            encap: None,
            mark: None,
            output_mark: None,
            if_id: None,
            egress_dscp: None,
        },
    };
    let inbound_policy = InstallPolicyRequest {
        parameters: PolicyParameters {
            selector: inbound_selector,
            direction: XfrmDirection::In,
            action: XfrmAction::Allow,
            priority: request.policy_priority,
            templates: vec![XfrmTemplate {
                id: policy_template_id(inbound_id, request_id),
                source_address: request.remote_tunnel_address,
                request_id,
                mode: request.mode,
            }],
            mark: None,
            if_id: None,
        },
    };
    let outbound_policy = InstallPolicyRequest {
        parameters: PolicyParameters {
            selector: outbound_selector,
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: request.policy_priority,
            templates: vec![XfrmTemplate {
                id: policy_template_id(outbound_id, request_id),
                source_address: request.local_tunnel_address,
                request_id,
                mode: request.mode,
            }],
            mark: None,
            if_id: None,
        },
    };

    Ok(Ikev2ChildSaXfrmRequests {
        inbound_sa,
        outbound_sa,
        inbound_policy,
        outbound_policy,
    })
}

fn policy_template_id(sa_id: XfrmId, request_id: Option<XfrmRequestId>) -> XfrmId {
    XfrmId {
        spi: if request_id.is_some() { 0 } else { sa_id.spi },
        ..sa_id
    }
}

fn child_sa_xfrm_keys_from_direction(
    profile: Ikev2ChildSaCryptoProfile,
    encryption_key: &[u8],
    integrity_key: &[u8],
) -> Result<Ikev2ChildSaXfrmKeys, Ikev2ChildSaKeyMaterialError> {
    if profile.encryption().is_aead() {
        if !integrity_key.is_empty() {
            return Err(Ikev2ChildSaKeyMaterialError::UnsupportedAlgorithmMapping);
        }
        let aead = match profile.encryption() {
            Ikev2EncryptionAlgorithm::AesGcm16_128
            | Ikev2EncryptionAlgorithm::AesGcm16_192
            | Ikev2EncryptionAlgorithm::AesGcm16_256 => AeadAlgorithm::rfc4106_gcm_aes(128),
            _ => return Err(Ikev2ChildSaKeyMaterialError::UnsupportedAlgorithmMapping),
        };
        return Ok(Ikev2ChildSaXfrmKeys::aead((
            aead,
            KeyMaterial::new(encryption_key.to_vec()),
        )));
    }

    let crypt = match profile.encryption() {
        Ikev2EncryptionAlgorithm::AesCbc128
        | Ikev2EncryptionAlgorithm::AesCbc192
        | Ikev2EncryptionAlgorithm::AesCbc256 => Algorithm::cbc_aes(),
        _ => return Err(Ikev2ChildSaKeyMaterialError::UnsupportedAlgorithmMapping),
    };
    let Some(integrity) = profile.integrity() else {
        return Err(Ikev2ChildSaKeyMaterialError::UnsupportedAlgorithmMapping);
    };
    Ok(Ikev2ChildSaXfrmKeys::new(
        Some((
            auth_algorithm_from_ikev2_integrity(integrity),
            KeyMaterial::new(integrity_key.to_vec()),
        )),
        Some((crypt, KeyMaterial::new(encryption_key.to_vec()))),
    ))
}

fn auth_algorithm_from_ikev2_integrity(integrity: Ikev2IntegrityAlgorithm) -> AuthAlgorithm {
    match integrity {
        Ikev2IntegrityAlgorithm::HmacSha2_256_128 => {
            AuthAlgorithm::hmac_sha256(integrity.icv_len_bits())
        }
        Ikev2IntegrityAlgorithm::HmacSha2_384_192 => {
            AuthAlgorithm::hmac_sha384(integrity.icv_len_bits())
        }
        Ikev2IntegrityAlgorithm::HmacSha2_512_256 => {
            AuthAlgorithm::hmac_sha512(integrity.icv_len_bits())
        }
    }
}

fn validate_request(request: &Ikev2ChildSaXfrmRequest) -> Result<(), Ikev2ChildSaXfrmError> {
    if request.negotiation.protocol_id != IKEV2_SECURITY_PROTOCOL_ID_ESP {
        return Err(Ikev2ChildSaXfrmError::UnsupportedProtocolId {
            protocol_id: request.negotiation.protocol_id,
        });
    }
    if request.responder_spi == 0 {
        return Err(Ikev2ChildSaXfrmError::ResponderSpiZero);
    }
    if request.inbound.is_empty() {
        return Err(Ikev2ChildSaXfrmError::MissingInboundKeyMaterial);
    }
    if request.outbound.is_empty() {
        return Err(Ikev2ChildSaXfrmError::MissingOutboundKeyMaterial);
    }
    if request.replay_window == 0 {
        return Err(Ikev2ChildSaXfrmError::ReplayWindowZero);
    }
    if !same_address_family(request.local_tunnel_address, request.remote_tunnel_address) {
        return Err(Ikev2ChildSaXfrmError::TunnelEndpointAddressFamilyMismatch);
    }
    Ok(())
}

fn initiator_spi_u32(spi: &[u8]) -> Result<u32, Ikev2ChildSaXfrmError> {
    let bytes: [u8; 4] = spi
        .try_into()
        .map_err(|_| Ikev2ChildSaXfrmError::InitiatorSpiInvalidLength { len: spi.len() })?;
    let spi = u32::from_be_bytes(bytes);
    if spi == 0 {
        return Err(Ikev2ChildSaXfrmError::InitiatorSpiZero);
    }
    Ok(spi)
}

/// Resolve one IKEv2 traffic selector into an XFRM base address and prefix
/// length.
///
/// IKEv2 carries selectors as an inclusive address range, but XFRM represents a
/// selector as a base address plus prefix length. A single-host range collapses
/// to a full-length prefix; a range that spans exactly one aligned CIDR block
/// collapses to that block's prefix. This is what lets the 3GPP route-all
/// responder selector (`0.0.0.0`-`255.255.255.255` or `::`-`ffff:...:ffff`)
/// install as a `/0` prefix.
fn selector_prefix(
    selector: &Ikev2TrafficSelectorBuild,
) -> Result<(IpAddress, u8), Ikev2ChildSaXfrmError> {
    match selector.ts_type {
        IKEV2_TS_IPV4_ADDR_RANGE => {
            let start: [u8; 4] = selector_octets(selector, &selector.start_address)?;
            let end: [u8; 4] = selector_octets(selector, &selector.end_address)?;
            Ok((IpAddress::Ipv4(start), cidr_prefix_len(&start, &end)?))
        }
        IKEV2_TS_IPV6_ADDR_RANGE => {
            let start: [u8; 16] = selector_octets(selector, &selector.start_address)?;
            let end: [u8; 16] = selector_octets(selector, &selector.end_address)?;
            Ok((IpAddress::Ipv6(start), cidr_prefix_len(&start, &end)?))
        }
        other => {
            Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressTypeUnsupported { ts_type: other })
        }
    }
}

fn selector_octets<const N: usize>(
    selector: &Ikev2TrafficSelectorBuild,
    address: &[u8],
) -> Result<[u8; N], Ikev2ChildSaXfrmError> {
    address.try_into().map_err(
        |_| Ikev2ChildSaXfrmError::TrafficSelectorAddressLengthInvalid {
            ts_type: selector.ts_type,
            len: address.len(),
        },
    )
}

/// Return the prefix length whose CIDR block is exactly the inclusive range
/// `start..=end`, or an error when the range is not a single aligned block.
///
/// `start` and `end` are the same length. `prefix` counts the leading bits on
/// which the two bounds agree; the range is a single prefix only when every bit
/// below that boundary is `0` in `start` (the network address) and `1` in `end`
/// (the last address of the block). Unaligned and inverted (`start > end`)
/// ranges fail one of those two conditions.
fn cidr_prefix_len(start: &[u8], end: &[u8]) -> Result<u8, Ikev2ChildSaXfrmError> {
    let prefix = leading_agreement_bits(start, end);
    if host_bits_all(start, prefix, false) && host_bits_all(end, prefix, true) {
        Ok(prefix)
    } else {
        Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressRangeUnsupported)
    }
}

/// Count the leading bits on which two equal-length byte strings agree.
fn leading_agreement_bits(start: &[u8], end: &[u8]) -> u8 {
    let mut bits: u8 = 0;
    for (left, right) in start.iter().zip(end.iter()) {
        let diff = left ^ right;
        if diff == 0 {
            bits += 8;
        } else {
            // A nonzero byte has 0..=7 leading zero bits, so the cast is exact.
            bits += diff.leading_zeros() as u8;
            break;
        }
    }
    bits
}

/// True when every bit at position `prefix` or later in `addr` equals `bit`.
///
/// Bits are numbered from the most significant bit of the first byte; positions
/// below `prefix` (the network portion) are ignored.
fn host_bits_all(addr: &[u8], prefix: u8, bit: bool) -> bool {
    let prefix = usize::from(prefix);
    let fill: u8 = if bit { 0xff } else { 0x00 };
    for (index, byte) in addr.iter().enumerate() {
        let byte_start = index * 8;
        let byte_end = byte_start + 8;
        if byte_end <= prefix {
            continue; // Byte lies entirely in the network portion.
        }
        let host_bits = byte_end - prefix.max(byte_start);
        let mask = low_bit_mask(host_bits);
        if (byte & mask) != (fill & mask) {
            return false;
        }
    }
    true
}

/// Mask selecting the low `count` bits (`count` in `1..=8`).
fn low_bit_mask(count: usize) -> u8 {
    if count >= 8 {
        0xff
    } else {
        (1u8 << count) - 1
    }
}

fn selector_protocol(initiator: u8, responder: u8) -> Result<u8, Ikev2ChildSaXfrmError> {
    match (initiator, responder) {
        (0, 0) => Ok(0),
        (0, protocol) | (protocol, 0) => Ok(protocol),
        (left, right) if left == right => Ok(left),
        _ => Err(Ikev2ChildSaXfrmError::TrafficSelectorProtocolMismatch {
            initiator,
            responder,
        }),
    }
}

fn selector_port(start: u16, end: u16) -> Result<u16, Ikev2ChildSaXfrmError> {
    if start == 0 && end == u16::MAX {
        return Ok(0);
    }
    if start == end {
        return Ok(start);
    }
    Err(Ikev2ChildSaXfrmError::TrafficSelectorPortRangeUnsupported { start, end })
}

fn xfrm_selector(
    source: (IpAddress, u8),
    destination: (IpAddress, u8),
    source_port: u16,
    destination_port: u16,
    protocol: u8,
) -> XfrmSelector {
    let mut selector = XfrmSelector::new(source.0, destination.0, protocol);
    selector.source_port = source_port;
    selector.destination_port = destination_port;
    selector.source_prefix_len = source.1;
    selector.destination_prefix_len = destination.1;
    selector
}

fn same_address_family(left: IpAddress, right: IpAddress) -> bool {
    matches!(
        (left, right),
        (IpAddress::Ipv4(_), IpAddress::Ipv4(_)) | (IpAddress::Ipv6(_), IpAddress::Ipv6(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{XFRM_AEAD_RFC4106_GCM_AES, XFRM_AUTH_HMAC_SHA256, XFRM_ENCR_CBC_AES};
    use opc_proto_ikev2::{
        Ikev2ChildSaCryptoProfile, Ikev2ChildSaNegotiation, Ikev2EncryptionAlgorithm,
        Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm, Ikev2SaInitCryptoErrorCode,
    };

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddress {
        IpAddress::Ipv4([a, b, c, d])
    }

    fn selector(address: [u8; 4], protocol: u8) -> Ikev2TrafficSelectorBuild {
        Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: protocol,
            start_port: 0,
            end_port: u16::MAX,
            start_address: address.to_vec(),
            end_address: address.to_vec(),
        }
    }

    fn range_selector(
        ts_type: u8,
        start: Vec<u8>,
        end: Vec<u8>,
        protocol: u8,
    ) -> Ikev2TrafficSelectorBuild {
        Ikev2TrafficSelectorBuild {
            ts_type,
            ip_protocol_id: protocol,
            start_port: 0,
            end_port: u16::MAX,
            start_address: start,
            end_address: end,
        }
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(hex.len() / 2);
        let bytes = hex.as_bytes();
        assert_eq!(bytes.len() % 2, 0);
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i]);
            let lo = hex_nibble(bytes[i + 1]);
            out.push((hi << 4) | lo);
            i += 2;
        }
        out
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hex digit"),
        }
    }

    fn keys(seed: u8) -> Ikev2ChildSaXfrmKeys {
        Ikev2ChildSaXfrmKeys::new(
            Some((
                AuthAlgorithm::hmac_sha256(128),
                KeyMaterial::new(vec![seed; 32]),
            )),
            Some((Algorithm::cbc_aes(), KeyMaterial::new(vec![seed; 20]))),
        )
    }

    fn aead_keys(seed: u8) -> Ikev2ChildSaXfrmKeys {
        Ikev2ChildSaXfrmKeys::aead((
            AeadAlgorithm::rfc4106_gcm_aes(128),
            KeyMaterial::new(vec![seed; 36]),
        ))
    }

    fn request() -> Ikev2ChildSaXfrmRequest {
        Ikev2ChildSaXfrmRequest {
            negotiation: Ikev2ChildSaNegotiation {
                proposal_number: 1,
                protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                initiator_spi: 0x1122_3344_u32.to_be_bytes().to_vec(),
                transforms: Vec::new(),
                initiator_traffic_selector: selector([10, 10, 0, 10], 17),
                responder_traffic_selector: selector([10, 20, 0, 20], 0),
            },
            local_tunnel_address: ipv4(192, 0, 2, 10),
            remote_tunnel_address: ipv4(198, 51, 100, 20),
            responder_spi: 0x5566_7788,
            inbound: keys(0xab),
            outbound: keys(0xcd),
            mode: XfrmMode::Tunnel,
            lifetime: LifetimeConfig::default(),
            replay_window: 32,
            policy_priority: 10_000,
        }
    }

    #[test]
    fn builds_bidirectional_sa_and_policy_requests() {
        let built = build_xfrm_requests_from_ikev2_child_sa(&request()).expect("request builds");

        assert_eq!(
            built.inbound_sa.parameters.id.destination,
            ipv4(192, 0, 2, 10)
        );
        assert_eq!(built.inbound_sa.parameters.id.spi, 0x5566_7788);
        assert_eq!(
            built.inbound_sa.parameters.source_address,
            ipv4(198, 51, 100, 20)
        );
        assert_eq!(
            built.inbound_sa.parameters.selector.source,
            ipv4(10, 10, 0, 10)
        );
        assert_eq!(
            built.inbound_sa.parameters.selector.destination,
            ipv4(10, 20, 0, 20)
        );
        assert_eq!(built.inbound_sa.parameters.selector.protocol, 17);
        assert_eq!(built.inbound_sa.parameters.request_id, None);
        assert_eq!(built.inbound_policy.parameters.direction, XfrmDirection::In);
        assert_eq!(
            built.inbound_policy.parameters.templates[0].id.spi,
            0x5566_7788
        );
        assert_eq!(
            built.inbound_policy.parameters.templates[0].request_id,
            None
        );

        assert_eq!(
            built.outbound_sa.parameters.id.destination,
            ipv4(198, 51, 100, 20)
        );
        assert_eq!(built.outbound_sa.parameters.id.spi, 0x1122_3344);
        assert_eq!(
            built.outbound_sa.parameters.source_address,
            ipv4(192, 0, 2, 10)
        );
        assert_eq!(
            built.outbound_sa.parameters.selector.source,
            ipv4(10, 20, 0, 20)
        );
        assert_eq!(
            built.outbound_sa.parameters.selector.destination,
            ipv4(10, 10, 0, 10)
        );
        assert_eq!(
            built.outbound_policy.parameters.direction,
            XfrmDirection::Out
        );

        let composites = built.composite_installs();
        assert_eq!(composites[0].sa.parameters.id.spi, 0x5566_7788);
        assert_eq!(composites[1].sa.parameters.id.spi, 0x1122_3344);
    }

    #[test]
    fn shared_request_id_builds_one_unpinned_policy_contract_for_rekey_overlap() {
        assert!(XfrmRequestId::new(0).is_none());
        let request_id = XfrmRequestId::new(7_001).expect("nonzero request ID");
        let old_request = request();
        let mut new_request = request();
        new_request.responder_spi = 0x99aa_bbcc;
        new_request.negotiation.initiator_spi = 0xddee_ff01_u32.to_be_bytes().to_vec();

        let old = build_xfrm_requests_from_ikev2_child_sa_with_request_id(&old_request, request_id)
            .expect("old Child SA");
        let new = build_xfrm_requests_from_ikev2_child_sa_with_request_id(&new_request, request_id)
            .expect("replacement Child SA");

        assert_ne!(old.inbound_sa.parameters.id, new.inbound_sa.parameters.id);
        assert_ne!(old.outbound_sa.parameters.id, new.outbound_sa.parameters.id);
        assert_eq!(old.inbound_sa.parameters.request_id, Some(request_id));
        assert_eq!(new.inbound_sa.parameters.request_id, Some(request_id));
        assert_eq!(old.outbound_sa.parameters.request_id, Some(request_id));
        assert_eq!(new.outbound_sa.parameters.request_id, Some(request_id));

        assert_eq!(old.inbound_policy, new.inbound_policy);
        assert_eq!(old.outbound_policy, new.outbound_policy);
        for policy in [&old.inbound_policy, &old.outbound_policy] {
            assert_eq!(policy.parameters.templates[0].id.spi, 0);
            assert_eq!(policy.parameters.templates[0].request_id, Some(request_id));
        }
    }

    #[test]
    fn rejects_non_esp_protocol() {
        let mut input = request();
        input.negotiation.protocol_id = 4;
        let err = build_xfrm_requests_from_ikev2_child_sa(&input)
            .expect_err("non-ESP Child SA must be rejected");
        assert_eq!(
            err,
            Ikev2ChildSaXfrmError::UnsupportedProtocolId { protocol_id: 4 }
        );
    }

    #[test]
    fn rejects_bad_spis() {
        let mut input = request();
        input.negotiation.initiator_spi = vec![1, 2, 3];
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::InitiatorSpiInvalidLength { len: 3 })
        ));

        input.negotiation.initiator_spi = 0_u32.to_be_bytes().to_vec();
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::InitiatorSpiZero)
        ));

        input.negotiation.initiator_spi = 1_u32.to_be_bytes().to_vec();
        input.responder_spi = 0;
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::ResponderSpiZero)
        ));
    }

    #[test]
    fn rejects_unrepresentable_traffic_selector_ranges() {
        // 10.10.0.10..10.10.0.12 is not a single aligned CIDR block.
        let mut input = request();
        input.negotiation.initiator_traffic_selector.end_address = vec![10, 10, 0, 12];
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressRangeUnsupported)
        ));

        // Start is not the network address of the block it would span.
        input = request();
        input.negotiation.responder_traffic_selector = range_selector(
            IKEV2_TS_IPV4_ADDR_RANGE,
            vec![10, 0, 0, 1],
            vec![10, 0, 0, 255],
            0,
        );
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressRangeUnsupported)
        ));

        // Inverted range (start > end) fails the host-bit conditions.
        input = request();
        input.negotiation.responder_traffic_selector = range_selector(
            IKEV2_TS_IPV4_ADDR_RANGE,
            vec![10, 0, 0, 11],
            vec![10, 0, 0, 10],
            0,
        );
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressRangeUnsupported)
        ));

        // Port ranges remain unrepresentable in the XFRM selector.
        input = request();
        input.negotiation.initiator_traffic_selector.start_port = 10;
        input.negotiation.initiator_traffic_selector.end_port = 20;
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorPortRangeUnsupported { start: 10, end: 20 })
        ));
    }

    #[test]
    fn accepts_route_all_ipv4_responder_selector() {
        let mut input = request();
        // Initiator keeps its single-host selector; the responder routes all
        // IPv4 traffic, as a 3GPP ePDG APN-anchored SA does.
        input.negotiation.responder_traffic_selector = range_selector(
            IKEV2_TS_IPV4_ADDR_RANGE,
            vec![0, 0, 0, 0],
            vec![255, 255, 255, 255],
            0,
        );

        let built = build_xfrm_requests_from_ikev2_child_sa(&input).expect("route-all builds");

        let inbound = &built.inbound_sa.parameters.selector;
        assert_eq!(inbound.source, ipv4(10, 10, 0, 10));
        assert_eq!(inbound.source_prefix_len, 32);
        assert_eq!(inbound.destination, ipv4(0, 0, 0, 0));
        assert_eq!(inbound.destination_prefix_len, 0);
        // Ports and protocol are untouched by the prefix handling.
        assert_eq!(inbound.protocol, 17);
        assert_eq!(inbound.source_port, 0);
        assert_eq!(inbound.destination_port, 0);

        let outbound = &built.outbound_sa.parameters.selector;
        assert_eq!(outbound.source, ipv4(0, 0, 0, 0));
        assert_eq!(outbound.source_prefix_len, 0);
        assert_eq!(outbound.destination, ipv4(10, 10, 0, 10));
        assert_eq!(outbound.destination_prefix_len, 32);

        // The SA and policy for each direction share one selector.
        assert_eq!(&built.inbound_policy.parameters.selector, inbound);
        assert_eq!(&built.outbound_policy.parameters.selector, outbound);
    }

    #[test]
    fn accepts_route_all_ipv6_responder_selector() {
        let host = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut input = request();
        input.negotiation.initiator_traffic_selector =
            range_selector(IKEV2_TS_IPV6_ADDR_RANGE, host.clone(), host.clone(), 0);
        input.negotiation.responder_traffic_selector =
            range_selector(IKEV2_TS_IPV6_ADDR_RANGE, vec![0x00; 16], vec![0xff; 16], 0);

        let built = build_xfrm_requests_from_ikev2_child_sa(&input).expect("ipv6 route-all builds");

        let inbound = &built.inbound_sa.parameters.selector;
        let host_bytes: [u8; 16] = host.as_slice().try_into().expect("16-byte host");
        assert_eq!(inbound.source, IpAddress::Ipv6(host_bytes));
        assert_eq!(inbound.source_prefix_len, 128);
        assert_eq!(inbound.destination, IpAddress::Ipv6([0; 16]));
        assert_eq!(inbound.destination_prefix_len, 0);
    }

    #[test]
    fn accepts_mid_range_cidr_block() {
        let mut input = request();
        input.negotiation.responder_traffic_selector = range_selector(
            IKEV2_TS_IPV4_ADDR_RANGE,
            vec![10, 0, 0, 0],
            vec![10, 0, 0, 255],
            0,
        );

        let built = build_xfrm_requests_from_ikev2_child_sa(&input).expect("/24 builds");

        let inbound = &built.inbound_sa.parameters.selector;
        assert_eq!(inbound.destination, ipv4(10, 0, 0, 0));
        assert_eq!(inbound.destination_prefix_len, 24);
    }

    #[test]
    fn accepts_slash_31_cidr_block() {
        // 10.10.0.10..10.10.0.11 is exactly 10.10.0.10/31.
        let mut input = request();
        input.negotiation.initiator_traffic_selector.end_address = vec![10, 10, 0, 11];

        let built = build_xfrm_requests_from_ikev2_child_sa(&input).expect("/31 builds");

        let inbound = &built.inbound_sa.parameters.selector;
        assert_eq!(inbound.source, ipv4(10, 10, 0, 10));
        assert_eq!(inbound.source_prefix_len, 31);
    }

    #[test]
    fn rejects_end_address_length_mismatch() {
        let mut input = request();
        input.negotiation.initiator_traffic_selector.end_address = vec![10, 10, 0, 10, 0];
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressLengthInvalid {
                ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
                len: 5
            })
        ));
    }

    #[test]
    fn rejects_ipv6_non_aligned_range() {
        let host = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut input = request();
        input.negotiation.initiator_traffic_selector =
            range_selector(IKEV2_TS_IPV6_ADDR_RANGE, host.clone(), host, 0);
        // All-zero start with an all-ones end except one cleared middle bit is
        // not a single prefix: the end's suffix is not all ones.
        let mut end = vec![0xff; 16];
        end[8] = 0x7f;
        input.negotiation.responder_traffic_selector =
            range_selector(IKEV2_TS_IPV6_ADDR_RANGE, vec![0x00; 16], end, 0);
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressRangeUnsupported)
        ));
    }

    #[tokio::test]
    async fn route_all_selector_prefixes_reach_mock_backend() {
        use crate::{install_sa_policy_with_rollback, MockOperation, MockXfrmBackend};

        let mut input = request();
        input.negotiation.responder_traffic_selector = range_selector(
            IKEV2_TS_IPV4_ADDR_RANGE,
            vec![0, 0, 0, 0],
            vec![255, 255, 255, 255],
            0,
        );
        let built = build_xfrm_requests_from_ikev2_child_sa(&input).expect("route-all builds");

        let backend = MockXfrmBackend::new();
        for composite in built.composite_installs() {
            let outcome = install_sa_policy_with_rollback(&backend, composite)
                .await
                .expect("mock install succeeds");
            assert!(outcome.applied);
        }

        // Inbound direction first: InstallSa then InstallPolicy, then outbound.
        let operations = backend.operations();
        assert_eq!(operations.len(), 4);

        let inbound_sa_prefixes = operations.iter().find_map(|op| match op {
            MockOperation::InstallSa { selector, .. } => {
                Some((selector.source_prefix_len, selector.destination_prefix_len))
            }
            _ => None,
        });
        assert_eq!(inbound_sa_prefixes, Some((32, 0)));

        // The inbound policy carries the same prefixes as its SA.
        let inbound_policy_prefixes = operations.iter().find_map(|op| match op {
            MockOperation::InstallPolicy { selector, .. } => {
                Some((selector.source_prefix_len, selector.destination_prefix_len))
            }
            _ => None,
        });
        assert_eq!(inbound_policy_prefixes, Some((32, 0)));

        // The outbound direction mirrors the prefixes onto the other side.
        let outbound_prefixes: Vec<(u8, u8)> = operations
            .iter()
            .filter_map(|op| match op {
                MockOperation::InstallSa { selector, .. }
                | MockOperation::InstallPolicy { selector, .. }
                    if selector.source_prefix_len == 0 =>
                {
                    Some((selector.source_prefix_len, selector.destination_prefix_len))
                }
                _ => None,
            })
            .collect();
        assert_eq!(outbound_prefixes, vec![(0, 32), (0, 32)]);
    }

    #[test]
    fn rejects_family_and_protocol_mismatches() {
        let mut input = request();
        input.negotiation.responder_traffic_selector.ts_type = IKEV2_TS_IPV6_ADDR_RANGE;
        input.negotiation.responder_traffic_selector.start_address = vec![0; 16];
        input.negotiation.responder_traffic_selector.end_address = vec![0; 16];
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressFamilyMismatch)
        ));

        input = request();
        input.negotiation.initiator_traffic_selector.ip_protocol_id = 6;
        input.negotiation.responder_traffic_selector.ip_protocol_id = 17;
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorProtocolMismatch {
                initiator: 6,
                responder: 17
            })
        ));
    }

    #[test]
    fn rejects_missing_directional_key_material() {
        let mut input = request();
        input.inbound = Ikev2ChildSaXfrmKeys::new(None, None);
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::MissingInboundKeyMaterial)
        ));

        input = request();
        input.outbound = Ikev2ChildSaXfrmKeys::new(None, None);
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::MissingOutboundKeyMaterial)
        ));
    }

    #[test]
    fn maps_aead_directional_keys_to_sa_parameters() {
        let mut input = request();
        input.inbound = aead_keys(0xab);
        input.outbound = aead_keys(0xcd);

        let built = build_xfrm_requests_from_ikev2_child_sa(&input).expect("request builds");

        assert!(built.inbound_sa.parameters.auth.is_none());
        assert!(built.inbound_sa.parameters.crypt.is_none());
        assert_eq!(
            built.inbound_sa.parameters.aead.as_ref().map(|(a, k)| (
                a.name.as_str(),
                a.icv_len_bits,
                k.len()
            )),
            Some((XFRM_AEAD_RFC4106_GCM_AES, 128, 36))
        );
        assert!(built.outbound_sa.parameters.auth.is_none());
        assert!(built.outbound_sa.parameters.crypt.is_none());
        assert_eq!(
            built.outbound_sa.parameters.aead.as_ref().map(|(a, k)| (
                a.name.as_str(),
                a.icv_len_bits,
                k.len()
            )),
            Some((XFRM_AEAD_RFC4106_GCM_AES, 128, 36))
        );
    }

    #[test]
    fn derives_child_sa_xfrm_keys_into_aead_slots_by_responder_direction() {
        let profile = Ikev2ChildSaCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::AesGcm16_256,
        );
        let keys =
            match derive_child_sa_xfrm_keys(profile, &[0x0f; 32], &[0xa1; 16], &[0xb2; 16], None) {
                Ok(keys) => keys,
                Err(error) => panic!("child SA XFRM key derivation failed: {error:?}"),
            };

        assert!(keys.inbound.auth.is_none());
        assert!(keys.inbound.crypt.is_none());
        let inbound = match &keys.inbound.aead {
            Some(value) => value,
            None => panic!("missing inbound AEAD keys"),
        };
        assert_eq!(inbound.0.name, XFRM_AEAD_RFC4106_GCM_AES);
        assert_eq!(inbound.0.icv_len_bits, 128);
        assert_eq!(
            inbound.1.as_bytes(),
            hex_to_bytes(
                "7ae50b9713ddfd346dbb3cfbe8b8d45a34c79925bedb4f4ae6a5ad6bc76d8ab578ea306c"
            )
        );

        assert!(keys.outbound.auth.is_none());
        assert!(keys.outbound.crypt.is_none());
        let outbound = match &keys.outbound.aead {
            Some(value) => value,
            None => panic!("missing outbound AEAD keys"),
        };
        assert_eq!(
            outbound.1.as_bytes(),
            hex_to_bytes(
                "e36f6fde3c1f71951c1fe8c6d7477a4a2adfe9b746fd3c6fd6be52da8c2afd17eeff3e2a"
            )
        );

        let mut input = request();
        input.inbound = keys.inbound;
        input.outbound = keys.outbound;
        let built = match build_xfrm_requests_from_ikev2_child_sa(&input) {
            Ok(built) => built,
            Err(error) => panic!("derived keys should build XFRM requests: {error:?}"),
        };
        assert_eq!(
            built
                .inbound_sa
                .parameters
                .aead
                .as_ref()
                .map(|(algorithm, key)| (
                    algorithm.name.as_str(),
                    algorithm.icv_len_bits,
                    key.len()
                )),
            Some((XFRM_AEAD_RFC4106_GCM_AES, 128, 36))
        );
        assert_eq!(
            built
                .outbound_sa
                .parameters
                .aead
                .as_ref()
                .map(|(algorithm, key)| (
                    algorithm.name.as_str(),
                    algorithm.icv_len_bits,
                    key.len()
                )),
            Some((XFRM_AEAD_RFC4106_GCM_AES, 128, 36))
        );
    }

    #[test]
    fn derives_child_sa_xfrm_keys_into_encrypt_then_mac_slots() {
        let profile = Ikev2ChildSaCryptoProfile::new_encrypt_then_mac(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::AesCbc256,
            Ikev2IntegrityAlgorithm::HmacSha2_256_128,
        );
        let keys =
            match derive_child_sa_xfrm_keys(profile, &[0x0f; 32], &[0xa1; 16], &[0xb2; 16], None) {
                Ok(keys) => keys,
                Err(error) => panic!("child SA XFRM key derivation failed: {error:?}"),
            };

        assert!(keys.inbound.aead.is_none());
        let inbound_crypt = match &keys.inbound.crypt {
            Some(value) => value,
            None => panic!("missing inbound crypt keys"),
        };
        assert_eq!(inbound_crypt.0.name, XFRM_ENCR_CBC_AES);
        assert_eq!(
            inbound_crypt.1.as_bytes(),
            hex_to_bytes("7ae50b9713ddfd346dbb3cfbe8b8d45a34c79925bedb4f4ae6a5ad6bc76d8ab5")
        );
        let inbound_auth = match &keys.inbound.auth {
            Some(value) => value,
            None => panic!("missing inbound auth keys"),
        };
        assert_eq!(inbound_auth.0.name, XFRM_AUTH_HMAC_SHA256);
        assert_eq!(inbound_auth.0.truncation_len_bits, 128);
        assert_eq!(inbound_auth.1.len(), 32);

        let outbound_crypt = match &keys.outbound.crypt {
            Some(value) => value,
            None => panic!("missing outbound crypt keys"),
        };
        assert_eq!(
            outbound_crypt.1.as_bytes(),
            hex_to_bytes("8c2afd17eeff3e2a77f1c49d07cb5a9456546102f02fe52ee641dd4e3bc207ce")
        );
    }

    #[test]
    fn child_sa_xfrm_key_derivation_errors_are_stable_and_redacted() {
        let profile = Ikev2ChildSaCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::AesGcm16_128,
        );
        let error =
            match derive_child_sa_xfrm_keys(profile, &[0x0f; 31], &[0xa1; 16], &[0xb2; 16], None) {
                Ok(value) => panic!("invalid SK_d unexpectedly derived keys: {value:?}"),
                Err(error) => error,
            };
        assert_eq!(
            error,
            Ikev2ChildSaKeyMaterialError::KeyDerivation(
                Ikev2SaInitCryptoErrorCode::InvalidKeyLength
            )
        );
        assert_eq!(error.as_str(), "ikev2_child_sa_keymat_derivation_failed");
        assert!(!format!("{error:?}").contains("0f0f"));
    }

    #[test]
    fn debug_redacts_key_material() {
        let debug = format!("{:?}", request());
        assert!(!debug.contains("abab"));
        assert!(!debug.contains("cdcd"));
        assert!(debug.contains("<redacted>"));
    }
}
