//! IKEv2 Child SA to XFRM request mapping.
//!
//! This module converts product-neutral Child SA negotiation intent from
//! `opc-proto-ikev2` into explicit XFRM SA and policy install requests. It does
//! not negotiate IKE, derive key material, allocate SPIs, or choose subscriber
//! policy.

use std::{error::Error, fmt};

use opc_proto_ikev2::{
    Ikev2ChildSaNegotiation, Ikev2TrafficSelectorBuild, IKEV2_TS_IPV4_ADDR_RANGE,
    IKEV2_TS_IPV6_ADDR_RANGE,
};

use crate::{
    Algorithm, AuthAlgorithm, InstallPolicyRequest, InstallSaRequest, IpAddress, KeyMaterial,
    LifetimeConfig, PolicyParameters, SaParameters, XfrmAction, XfrmCompositeInstallRequest,
    XfrmDirection, XfrmId, XfrmMode, XfrmSelector, XfrmTemplate,
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
}

impl Ikev2ChildSaXfrmKeys {
    /// Create directional XFRM key material.
    pub fn new(
        auth: Option<(AuthAlgorithm, KeyMaterial)>,
        crypt: Option<(Algorithm, KeyMaterial)>,
    ) -> Self {
        Self { auth, crypt }
    }

    /// Return true when no authentication or encryption key material is present.
    pub fn is_empty(&self) -> bool {
        self.auth.is_none() && self.crypt.is_none()
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
    /// The traffic selector address range cannot be represented by this XFRM model.
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

/// Build bidirectional XFRM SA and policy install requests for a Child SA.
///
/// # Errors
///
/// Returns [`Ikev2ChildSaXfrmError`] when the negotiation uses a protocol,
/// SPI, selector range, endpoint family, or key-material shape that the current
/// SDK XFRM model cannot represent exactly.
pub fn build_xfrm_requests_from_ikev2_child_sa(
    request: &Ikev2ChildSaXfrmRequest,
) -> Result<Ikev2ChildSaXfrmRequests, Ikev2ChildSaXfrmError> {
    validate_request(request)?;

    let initiator_spi = initiator_spi_u32(&request.negotiation.initiator_spi)?;
    let initiator_selector = selector_address(&request.negotiation.initiator_traffic_selector)?;
    let responder_selector = selector_address(&request.negotiation.responder_traffic_selector)?;
    if !same_address_family(initiator_selector, responder_selector) {
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
            auth: request.inbound.auth.clone(),
            crypt: request.inbound.crypt.clone(),
            mode: request.mode,
            lifetime: request.lifetime,
            replay_window: request.replay_window,
        },
    };
    let outbound_sa = InstallSaRequest {
        parameters: SaParameters {
            selector: outbound_selector.clone(),
            id: outbound_id,
            source_address: request.local_tunnel_address,
            auth: request.outbound.auth.clone(),
            crypt: request.outbound.crypt.clone(),
            mode: request.mode,
            lifetime: request.lifetime,
            replay_window: request.replay_window,
        },
    };
    let inbound_policy = InstallPolicyRequest {
        parameters: PolicyParameters {
            selector: inbound_selector,
            direction: XfrmDirection::In,
            action: XfrmAction::Allow,
            priority: request.policy_priority,
            templates: vec![XfrmTemplate {
                id: inbound_id,
                source_address: request.remote_tunnel_address,
                mode: request.mode,
            }],
        },
    };
    let outbound_policy = InstallPolicyRequest {
        parameters: PolicyParameters {
            selector: outbound_selector,
            direction: XfrmDirection::Out,
            action: XfrmAction::Allow,
            priority: request.policy_priority,
            templates: vec![XfrmTemplate {
                id: outbound_id,
                source_address: request.local_tunnel_address,
                mode: request.mode,
            }],
        },
    };

    Ok(Ikev2ChildSaXfrmRequests {
        inbound_sa,
        outbound_sa,
        inbound_policy,
        outbound_policy,
    })
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

fn selector_address(
    selector: &Ikev2TrafficSelectorBuild,
) -> Result<IpAddress, Ikev2ChildSaXfrmError> {
    if selector.start_address != selector.end_address {
        return Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressRangeUnsupported);
    }

    match selector.ts_type {
        IKEV2_TS_IPV4_ADDR_RANGE => {
            let bytes: [u8; 4] = selector.start_address.as_slice().try_into().map_err(|_| {
                Ikev2ChildSaXfrmError::TrafficSelectorAddressLengthInvalid {
                    ts_type: selector.ts_type,
                    len: selector.start_address.len(),
                }
            })?;
            Ok(IpAddress::Ipv4(bytes))
        }
        IKEV2_TS_IPV6_ADDR_RANGE => {
            let bytes: [u8; 16] = selector.start_address.as_slice().try_into().map_err(|_| {
                Ikev2ChildSaXfrmError::TrafficSelectorAddressLengthInvalid {
                    ts_type: selector.ts_type,
                    len: selector.start_address.len(),
                }
            })?;
            Ok(IpAddress::Ipv6(bytes))
        }
        other => {
            Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressTypeUnsupported { ts_type: other })
        }
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
    source: IpAddress,
    destination: IpAddress,
    source_port: u16,
    destination_port: u16,
    protocol: u8,
) -> XfrmSelector {
    let mut selector = XfrmSelector::new(source, destination, protocol);
    selector.source_port = source_port;
    selector.destination_port = destination_port;
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
    use opc_proto_ikev2::Ikev2ChildSaNegotiation;

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

    fn keys(seed: u8) -> Ikev2ChildSaXfrmKeys {
        Ikev2ChildSaXfrmKeys::new(
            Some((
                AuthAlgorithm::new("hmac-sha256", 128),
                KeyMaterial::new(vec![seed; 32]),
            )),
            Some((
                Algorithm::new("rfc4106(gcm(aes))"),
                KeyMaterial::new(vec![seed; 20]),
            )),
        )
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
        assert_eq!(built.inbound_policy.parameters.direction, XfrmDirection::In);

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
        let mut input = request();
        input.negotiation.initiator_traffic_selector.end_address = vec![10, 10, 0, 11];
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorAddressRangeUnsupported)
        ));

        input = request();
        input.negotiation.initiator_traffic_selector.start_port = 10;
        input.negotiation.initiator_traffic_selector.end_port = 20;
        assert!(matches!(
            build_xfrm_requests_from_ikev2_child_sa(&input),
            Err(Ikev2ChildSaXfrmError::TrafficSelectorPortRangeUnsupported { start: 10, end: 20 })
        ));
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
    fn debug_redacts_key_material() {
        let debug = format!("{:?}", request());
        assert!(!debug.contains("abab"));
        assert!(!debug.contains("cdcd"));
        assert!(debug.contains("<redacted>"));
    }
}
