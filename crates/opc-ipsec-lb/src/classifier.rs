//! SWu UDP/500 and UDP/4500 packet classification.

use opc_ipsec_lb_ebpf_common::bootstrap_tag;

use crate::error::IpsecLbError;
use crate::model::{IpAddress, SteerKey};
use crate::selector::{RendezvousSelector, SelectionKey, ShardSet};

const IKE_HEADER_LEN: usize = 28;
const IKEV2_MAJOR_VERSION: u8 = 2;
const EXCHANGE_TYPE_IKE_SA_INIT: u8 = 34;
const UDP_PORT_IKE: u16 = 500;
const UDP_PORT_IKE_NATT: u16 = 4500;
const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];
const NAT_T_KEEPALIVE: [u8; 1] = [0xff];
const ESP_HEADER_PREFIX_LEN: usize = 8;

/// ESP IP-fragmentation handling posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspFragmentPosture {
    /// Deployment prevents ESP IP fragmentation via MTU/DF posture.
    PreventIpFragmentation,
    /// Deployment reassembles fragments before steering.
    ReassembleBeforeSteer,
}

/// IP fragmentation metadata supplied by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct IpFragment {
    /// Fragment offset in 8-octet units.
    pub offset: u16,
    /// More-fragments flag.
    pub more_fragments: bool,
}

impl IpFragment {
    /// True for a non-first fragment that lacks UDP/ESP headers.
    #[must_use]
    pub const fn is_non_first(self) -> bool {
        self.offset != 0
    }
}

/// Classifier configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwuClassifierConfig<'a> {
    /// Current shard set used for IKE_SA_INIT bootstrap.
    pub shards: &'a ShardSet,
    /// Number of high-order routing-tag bits used for IKE responder SPIs. Must
    /// match the datapath `XdpConfig.ike_tag_bits`, so the userspace and XDP
    /// bootstrap decisions steer an initial IKE_SA_INIT to the same shard.
    pub bootstrap_tag_bits: u8,
    /// ESP IP-fragment posture.
    pub esp_fragment_posture: EspFragmentPosture,
}

/// Ingress SWu packet view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwuPacket<'a> {
    /// UDP destination port.
    pub udp_destination_port: u16,
    /// Source IP observed at the edge.
    pub source_ip: IpAddress,
    /// UDP datagram payload.
    pub datagram: &'a [u8],
    /// Optional IP fragmentation metadata.
    pub fragment: Option<IpFragment>,
}

/// Packet classification outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwuClassification {
    /// Accepted for steering.
    Steer {
        /// Key extracted from packet headers.
        key: SteerKey,
        /// Bootstrap shard selected for initial IKE_SA_INIT packets.
        bootstrap_shard: Option<crate::model::ShardId>,
    },
    /// NAT traversal keepalive consumed at the edge.
    NatKeepalive,
    /// Non-first fragment requires configured reassembly.
    NeedsReassembly,
    /// Rejected with a stable reason.
    Rejected {
        /// Stable rejection code.
        code: &'static str,
    },
}

impl SwuClassification {
    /// Stable classification code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Steer {
                key: SteerKey::IkeResponderSpi(_),
                ..
            } => "ike_responder_spi",
            Self::Steer {
                key: SteerKey::IkeInit { .. },
                ..
            } => "ike_sa_init_bootstrap",
            Self::Steer {
                key: SteerKey::EspSpi(_),
                ..
            } => "esp_in_udp",
            Self::NatKeepalive => "natt_keepalive",
            Self::NeedsReassembly => "ip_fragment_needs_reassembly",
            Self::Rejected { code } => code,
        }
    }

    /// Convert rejection into an error.
    pub fn accepted(self) -> Result<Self, IpsecLbError> {
        match self {
            Self::Rejected { code } => Err(IpsecLbError::packet_rejected(code)),
            _ => Ok(self),
        }
    }
}

/// Classify an ingress SWu packet.
#[must_use]
pub fn classify_swu_packet(
    packet: SwuPacket<'_>,
    config: SwuClassifierConfig<'_>,
) -> SwuClassification {
    if let Some(fragment) = packet.fragment {
        if fragment.is_non_first() {
            return match config.esp_fragment_posture {
                EspFragmentPosture::PreventIpFragmentation => SwuClassification::Rejected {
                    code: "unexpected_non_first_ip_fragment",
                },
                EspFragmentPosture::ReassembleBeforeSteer => SwuClassification::NeedsReassembly,
            };
        }
    }

    match packet.udp_destination_port {
        UDP_PORT_IKE => classify_ike(packet.datagram, packet.source_ip, config),
        UDP_PORT_IKE_NATT => classify_udp_4500(packet.datagram, packet.source_ip, config),
        _ => SwuClassification::Rejected {
            code: "unsupported_udp_port",
        },
    }
}

fn classify_udp_4500(
    datagram: &[u8],
    source_ip: IpAddress,
    config: SwuClassifierConfig<'_>,
) -> SwuClassification {
    if datagram == NAT_T_KEEPALIVE {
        return SwuClassification::NatKeepalive;
    }
    if datagram.starts_with(&NON_ESP_MARKER) {
        return classify_ike(&datagram[NON_ESP_MARKER.len()..], source_ip, config);
    }
    if datagram.len() < ESP_HEADER_PREFIX_LEN {
        return SwuClassification::Rejected {
            code: "runt_esp_in_udp",
        };
    }
    let spi = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
    if spi == 0 {
        return SwuClassification::Rejected {
            code: "zero_esp_spi",
        };
    }
    SwuClassification::Steer {
        key: SteerKey::EspSpi(spi),
        bootstrap_shard: None,
    }
}

fn classify_ike(
    ike: &[u8],
    source_ip: IpAddress,
    config: SwuClassifierConfig<'_>,
) -> SwuClassification {
    let Some(header) = parse_ike_header(ike) else {
        return SwuClassification::Rejected {
            code: "malformed_ike_header",
        };
    };

    if header.responder_spi == 0 {
        if header.exchange_type != EXCHANGE_TYPE_IKE_SA_INIT {
            return SwuClassification::Rejected {
                code: "zero_responder_spi_outside_ike_sa_init",
            };
        }
        // Steer an initial IKE_SA_INIT (no allocated SPI yet) to the shard that
        // owns its bootstrap tag, using the SAME FNV tag the XDP datapath computes
        // (`ebpf_common::bootstrap_tag`) and the SAME rendezvous tag->shard mapping
        // the allocator's `decode` uses — so userspace and datapath agree.
        let tag = match source_ip {
            IpAddress::V4(octets) => {
                bootstrap_tag(header.initiator_spi, &octets, config.bootstrap_tag_bits)
            }
            IpAddress::V6(octets) => {
                bootstrap_tag(header.initiator_spi, &octets, config.bootstrap_tag_bits)
            }
        };
        let Some(tag) = tag else {
            return SwuClassification::Rejected {
                code: "invalid_bootstrap_tag_bits",
            };
        };
        let selector = RendezvousSelector;
        let Ok(bootstrap_shard) =
            selector.select(config.shards, &SelectionKey::Tag(u64::from(tag)))
        else {
            return SwuClassification::Rejected {
                code: "no_bootstrap_shard",
            };
        };
        return SwuClassification::Steer {
            key: SteerKey::IkeInit {
                initiator_spi: header.initiator_spi,
                source_ip,
            },
            bootstrap_shard: Some(bootstrap_shard),
        };
    }

    SwuClassification::Steer {
        key: SteerKey::IkeResponderSpi(header.responder_spi),
        bootstrap_shard: None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IkeHeader {
    initiator_spi: u64,
    responder_spi: u64,
    exchange_type: u8,
}

fn parse_ike_header(input: &[u8]) -> Option<IkeHeader> {
    if input.len() < IKE_HEADER_LEN {
        return None;
    }
    let version = input[17];
    if (version >> 4) != IKEV2_MAJOR_VERSION {
        return None;
    }
    let declared_len = u32::from_be_bytes([input[24], input[25], input[26], input[27]]) as usize;
    if declared_len < IKE_HEADER_LEN || declared_len > input.len() {
        return None;
    }
    Some(IkeHeader {
        initiator_spi: u64::from_be_bytes(input[0..8].try_into().ok()?),
        responder_spi: u64::from_be_bytes(input[8..16].try_into().ok()?),
        exchange_type: input[18],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ShardId;

    fn shards() -> ShardSet {
        ShardSet::new(vec![ShardId::new(0), ShardId::new(1), ShardId::new(2)]).unwrap()
    }

    fn config(shards: &ShardSet) -> SwuClassifierConfig<'_> {
        SwuClassifierConfig {
            shards,
            bootstrap_tag_bits: 8,
            esp_fragment_posture: EspFragmentPosture::PreventIpFragmentation,
        }
    }

    fn ike_header(initiator_spi: u64, responder_spi: u64, exchange_type: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; IKE_HEADER_LEN];
        bytes[0..8].copy_from_slice(&initiator_spi.to_be_bytes());
        bytes[8..16].copy_from_slice(&responder_spi.to_be_bytes());
        bytes[17] = 0x20;
        bytes[18] = exchange_type;
        bytes[24..28].copy_from_slice(&(IKE_HEADER_LEN as u32).to_be_bytes());
        bytes
    }

    #[test]
    fn udp_500_initial_ike_sa_init_uses_bootstrap_key() {
        let shards = shards();
        let packet = SwuPacket {
            udp_destination_port: 500,
            source_ip: IpAddress::V4([198, 51, 100, 7]),
            datagram: &ike_header(0x1111, 0, EXCHANGE_TYPE_IKE_SA_INIT),
            fragment: None,
        };
        let classification = classify_swu_packet(packet, config(&shards));
        assert_eq!(classification.code(), "ike_sa_init_bootstrap");
        assert!(matches!(
            classification,
            SwuClassification::Steer {
                key: SteerKey::IkeInit { .. },
                bootstrap_shard: Some(_)
            }
        ));
    }

    #[test]
    fn udp_4500_non_esp_marker_classifies_ike_on_responder_spi() {
        let shards = shards();
        let mut datagram = NON_ESP_MARKER.to_vec();
        datagram.extend_from_slice(&ike_header(0x1111, 0x2222, 35));
        let classification = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: IpAddress::V4([203, 0, 113, 9]),
                datagram: &datagram,
                fragment: None,
            },
            config(&shards),
        );
        assert_eq!(classification.code(), "ike_responder_spi");
    }

    #[test]
    fn udp_4500_without_marker_classifies_esp_spi() {
        let shards = shards();
        let datagram = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 1];
        let classification = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: IpAddress::V4([203, 0, 113, 9]),
                datagram: &datagram,
                fragment: None,
            },
            config(&shards),
        );
        assert!(matches!(
            classification,
            SwuClassification::Steer {
                key: SteerKey::EspSpi(0x1234_5678),
                ..
            }
        ));
    }

    #[test]
    fn mobike_source_change_does_not_change_nonzero_ike_steer_key() {
        let shards = shards();
        let ike = ike_header(0x1111, 0x2222, 37);
        let first = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 500,
                source_ip: IpAddress::V4([198, 51, 100, 1]),
                datagram: &ike,
                fragment: None,
            },
            config(&shards),
        );
        let second = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 500,
                source_ip: IpAddress::V4([198, 51, 100, 2]),
                datagram: &ike,
                fragment: None,
            },
            config(&shards),
        );
        assert_eq!(first, second);
    }

    #[test]
    fn malformed_and_runt_packets_fail_closed() {
        let shards = shards();
        assert_eq!(
            classify_swu_packet(
                SwuPacket {
                    udp_destination_port: 500,
                    source_ip: IpAddress::V4([1, 1, 1, 1]),
                    datagram: &[0u8; 8],
                    fragment: None,
                },
                config(&shards),
            )
            .code(),
            "malformed_ike_header"
        );
        assert_eq!(
            classify_swu_packet(
                SwuPacket {
                    udp_destination_port: 4500,
                    source_ip: IpAddress::V4([1, 1, 1, 1]),
                    datagram: &[1, 2, 3],
                    fragment: None,
                },
                config(&shards),
            )
            .code(),
            "runt_esp_in_udp"
        );
    }

    #[test]
    fn non_first_ip_fragment_is_not_silently_dropped() {
        let shards = shards();
        let classification = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: IpAddress::V4([1, 1, 1, 1]),
                datagram: &[],
                fragment: Some(IpFragment {
                    offset: 1,
                    more_fragments: false,
                }),
            },
            config(&shards),
        );
        assert_eq!(classification.code(), "unexpected_non_first_ip_fragment");

        let classification = classify_swu_packet(
            SwuPacket {
                udp_destination_port: 4500,
                source_ip: IpAddress::V4([1, 1, 1, 1]),
                datagram: &[],
                fragment: Some(IpFragment {
                    offset: 1,
                    more_fragments: true,
                }),
            },
            SwuClassifierConfig {
                shards: &shards,
                bootstrap_tag_bits: 8,
                esp_fragment_posture: EspFragmentPosture::ReassembleBeforeSteer,
            },
        );
        assert_eq!(classification, SwuClassification::NeedsReassembly);
    }
}
