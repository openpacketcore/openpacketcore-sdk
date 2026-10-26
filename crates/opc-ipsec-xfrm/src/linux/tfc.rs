//! RFC4303 dummy submission through the existing kernel SA.

use super::*;

const OPERATION: &str = "tfc_dummy_open";
const DUMMY_FLAG: u8 = 8;
const DUMMY_CAPABILITY_ATTRIBUTE: u16 = 3;
const MAX_PAYLOAD: usize = 65_495;

/// A protocol-59 sender bound to the calling thread's current network namespace.
///
/// Each packet requires the exact ESP template supplied at construction. Linux
/// owns sequence/nonce allocation, encryption and lifetime enforcement on that
/// same SA, including when ordinary traffic uses it concurrently. The sender
/// never reads keys or sequence counters and installs no global policy or SA.
/// Dropping it removes its private socket policy.
///
/// Transport mode works on stock Linux. Tunnel mode requires the versioned
/// OPCTFC01 capability from `kernel/xfrm-tfc-dummy/linux.patch`; absence is
/// rejected before opening the raw socket. This is a maintained kernel patch,
/// not an upstream Linux capability. Hardware-offloaded and stacked transforms
/// are outside that patch's profile and fail closed.
///
/// The template uses lookup mark zero and interface ID zero; callers must keep
/// its public tuple unique, including overlapping mark masks. Its selector must
/// admit the chosen source/destination and protocol 59. Namespace choice, SA
/// lifecycle, peer negotiation, scheduling and rate limits remain caller-owned.
/// Fence this producer with other egress before recovery, relocation or SA
/// replacement, then recreate it. This socket is not durable SA incarnation
/// authority. Stock transport lookup retains normal key-manager ACQUIRE behavior
/// when an SA is missing; the tunnel patch suppresses that request.
pub struct EspTfcDummySender {
    socket: opc_linux_xfrm_sys::TfcDummySocket,
}

impl fmt::Debug for EspTfcDummySender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EspTfcDummySender").finish_non_exhaustive()
    }
}

impl EspTfcDummySender {
    /// Require an installed ESP SA through a mandatory per-socket policy.
    /// `source` and `destination` are inner addresses in tunnel mode and must
    /// equal the template endpoints in transport mode. Requires CAP_NET_RAW
    /// and CAP_NET_ADMIN. Opening can fail if the exact SA or route is absent.
    /// The returned socket stays in this namespace even if its caller moves.
    pub fn open_current_namespace(
        source: IpAddress,
        destination: IpAddress,
        sa: XfrmTemplate,
    ) -> Result<Self, XfrmError> {
        let policy = encode_dummy_policy(source, destination, sa)?;
        if sa.mode == XfrmMode::Tunnel {
            let mut session = NetlinkXfrmTransport.open_session(OPERATION)?;
            session.send(&encode_netlink_message(
                XFRM_MSG_GETSADINFO,
                NLM_F_REQUEST,
                1,
                &0_u32.to_ne_bytes(),
            )?)?;
            receive_sad_info(
                OPERATION,
                LinuxXfrmBackendConfig::default(),
                |buffer| session.receive(buffer),
                |datagram| validate_dummy_capability(datagram, source, sa.id.destination),
            )?;
        }
        let socket =
            opc_linux_xfrm_sys::TfcDummySocket::open(std_ip(source), std_ip(destination), &policy)
                .map_err(|error| map_open_error(OPERATION, error))?;
        Ok(Self { socket })
    }

    /// Submit one dummy containing `payload_len` zero filler bytes (1..=65,495).
    ///
    /// The kernel adds IP/ESP overhead and any configured TFC padding; this is
    /// not a requested wire length. Path-MTU and SA limits can reject smaller
    /// sizes. Success means local submission, not delivery. An I/O error must
    /// not be interpreted as proof that no sequence number was consumed.
    pub fn send(&self, payload_len: usize) -> Result<(), XfrmError> {
        validate_payload_len(payload_len)?;
        let sent = self
            .socket
            .send(&vec![0; payload_len])
            .map_err(|error| XfrmError::io("tfc_dummy_send", error))?;
        if sent != payload_len {
            return Err(XfrmError::io(
                "tfc_dummy_send",
                io::Error::from(io::ErrorKind::WriteZero),
            ));
        }
        Ok(())
    }
}

fn validate_payload_len(length: usize) -> Result<(), XfrmError> {
    if !(1..=MAX_PAYLOAD).contains(&length) {
        return Err(XfrmError::invalid_config(
            "tfc_dummy.payload_len",
            "must be between 1 and 65495",
        ));
    }
    Ok(())
}

fn std_ip(address: IpAddress) -> std::net::IpAddr {
    match address {
        IpAddress::Ipv4(octets) => std::net::IpAddr::V4(octets.into()),
        IpAddress::Ipv6(octets) => std::net::IpAddr::V6(octets.into()),
    }
}

fn encode_dummy_policy(
    source: IpAddress,
    destination: IpAddress,
    sa: XfrmTemplate,
) -> Result<SensitiveBuffer, XfrmError> {
    validate_same_family(source, destination, "tfc_dummy.family")?;
    if sa.id.protocol != 50
        || sa.id.spi == 0
        || !matches!(sa.mode, XfrmMode::Transport | XfrmMode::Tunnel)
    {
        return Err(XfrmError::invalid_config(
            "tfc_dummy.sa",
            "requires an exact ESP transport or tunnel SA",
        ));
    }
    for address in [source, destination, sa.source_address, sa.id.destination] {
        let ip = std_ip(address);
        if ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, std::net::IpAddr::V4(ip) if ip.is_broadcast())
            || matches!(ip, std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            return Err(XfrmError::invalid_config(
                "tfc_dummy.address",
                "requires unicast addresses without an IPv6 scope ID",
            ));
        }
    }
    if sa.mode == XfrmMode::Transport
        && (source != sa.source_address || destination != sa.id.destination)
    {
        return Err(XfrmError::invalid_config(
            "tfc_dummy.endpoints",
            "transport endpoints must equal the SA endpoints",
        ));
    }
    let parameters = PolicyParameters {
        selector: XfrmSelector::new(source, destination, 59),
        direction: XfrmDirection::Out,
        action: XfrmAction::Allow,
        priority: 0,
        templates: vec![sa],
        mark: None,
        if_id: None,
    };
    let mut policy = encode_policy_info(&parameters)?;
    // Socket policies contain bare templates, without netlink attribute headers.
    policy.truncate(XFRM_USER_POLICY_INFO_LEN);
    if sa.mode == XfrmMode::Tunnel {
        policy[162] = DUMMY_FLAG;
    }
    encode_template(&mut policy, &sa)?;
    Ok(policy)
}

fn validate_dummy_capability(
    datagram: &[u8],
    inner: IpAddress,
    outer: IpAddress,
) -> Result<(), XfrmError> {
    parse_sad_state_count_reply(OPERATION, datagram, 1)?;
    let length = read_u32_ne(datagram, 0)? as usize;
    let capability = unique_route_attribute(
        &datagram[NETLINK_HEADER_LEN..length],
        4,
        DUMMY_CAPABILITY_ATTRIBUTE,
        OPERATION,
    )?;
    let unsupported = || XfrmError::UnsupportedFeature {
        feature: "esp_tunnel_tfc_dummy_v1",
    };
    let value = capability.ok_or_else(unsupported)?;
    if value.len() != 12 || &value[..8] != b"OPCTFC01" {
        return Err(unsupported());
    }
    let mask = read_u32_ne(value, 8)?;
    let required = (if inner.is_ipv4() { 1 } else { 2 }) | (if outer.is_ipv4() { 1 } else { 2 });
    if mask & !3 != 0 || mask & required != required {
        return Err(unsupported());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses() -> (IpAddress, IpAddress, XfrmTemplate) {
        let source = IpAddress::Ipv4([192, 0, 2, 10]);
        let destination = IpAddress::Ipv4([192, 0, 2, 20]);
        (
            source,
            destination,
            XfrmTemplate {
                id: XfrmId {
                    destination,
                    spi: 0x124400,
                    protocol: 50,
                },
                source_address: source,
                request_id: XfrmRequestId::new(42),
                mode: XfrmMode::Tunnel,
            },
        )
    }

    fn reply(value: Option<&[u8]>) -> SensitiveBuffer {
        let mut body = vec![0; 4];
        append_attr(&mut body, XFRMA_SAD_CNT, &1_u32.to_ne_bytes()).unwrap();
        if let Some(value) = value {
            append_attr(&mut body, DUMMY_CAPABILITY_ATTRIBUTE, value).unwrap();
        }
        encode_netlink_message(XFRM_MSG_NEWSADINFO, 0, 1, &body).unwrap()
    }

    #[test]
    fn dummy_capability_requires_exact_magic_version_families_and_netlink_framing() {
        let (source, destination, _) = addresses();
        let mut value = b"OPCTFC01".to_vec();
        value.extend_from_slice(&3_u32.to_ne_bytes());
        assert!(validate_dummy_capability(&reply(Some(&value)), source, destination).is_ok());
        assert!(validate_dummy_capability(&reply(None), source, destination).is_err());
        assert!(
            validate_dummy_capability(&reply(Some(&value)), source, IpAddress::Ipv6([1; 16]))
                .is_ok()
        );
        for offset in 0..8 {
            let mut wrong = value.clone();
            wrong[offset] ^= 1;
            assert!(validate_dummy_capability(&reply(Some(&wrong)), source, destination).is_err());
        }
        for length in 0..value.len() {
            assert!(
                validate_dummy_capability(&reply(Some(&value[..length])), source, destination)
                    .is_err()
            );
        }
        for mask in [0_u32, 2, 4, u32::MAX] {
            value[8..].copy_from_slice(&mask.to_ne_bytes());
            assert!(validate_dummy_capability(&reply(Some(&value)), source, destination).is_err());
        }
        value[8..].copy_from_slice(&1_u32.to_ne_bytes());
        assert!(validate_dummy_capability(
            &reply(Some(&value)),
            IpAddress::Ipv6([1; 16]),
            destination
        )
        .is_err());
        let mut packet = reply(Some(&value));
        packet[8] = 2;
        assert!(validate_dummy_capability(&packet, source, destination).is_err());
        packet = reply(Some(&value));
        packet[4] = XFRM_MSG_NEWSA as u8;
        assert!(validate_dummy_capability(&packet, source, destination).is_err());
        let mut body = reply(Some(&value))[NETLINK_HEADER_LEN..].to_vec();
        append_attr(&mut body, DUMMY_CAPABILITY_ATTRIBUTE, &value).unwrap();
        assert!(validate_dummy_capability(
            &encode_netlink_message(XFRM_MSG_NEWSADINFO, 0, 1, &body).unwrap(),
            source,
            destination
        )
        .is_err());
    }

    #[test]
    fn dummy_policy_is_an_exact_required_socket_template_and_transport_needs_no_patch_flag() {
        let (source, destination, mut sa) = addresses();
        let policy = encode_dummy_policy(source, destination, sa).unwrap();
        assert_eq!(policy.len(), 232);
        assert_eq!(&policy[40..42], &AF_INET.to_ne_bytes());
        assert_eq!(&policy[42..45], &[32, 32, 59]);
        assert_eq!(&policy[160..164], &[1, 0, 8, 0]);
        assert_eq!(&policy[184..192], &[0, 0x12, 0x44, 0, 50, 0, 0, 0]);
        assert_eq!(&policy[216..220], &[1, 0, 0, 0]);
        sa.mode = XfrmMode::Transport;
        let policy = encode_dummy_policy(source, destination, sa).unwrap();
        assert_eq!(policy[162], 0);
        assert_eq!(policy[216], 0);
        assert_eq!(policy[218], 0);
        assert!(encode_dummy_policy(IpAddress::Ipv4([192, 0, 2, 11]), destination, sa).is_err());
        sa.mode = XfrmMode::Beet;
        assert!(encode_dummy_policy(source, destination, sa).is_err());
        sa.mode = XfrmMode::Tunnel;
        sa.id.spi = 0;
        assert!(encode_dummy_policy(source, destination, sa).is_err());
        sa.id.spi = 1;
        sa.id.protocol = 51;
        assert!(encode_dummy_policy(source, destination, sa).is_err());
        sa.id.protocol = 50;
        assert!(encode_dummy_policy(IpAddress::Ipv6([1; 16]), destination, sa).is_err());
        assert!(encode_dummy_policy(IpAddress::Ipv4([0; 4]), destination, sa).is_err());
        assert!(encode_dummy_policy(source, IpAddress::Ipv4([224, 0, 0, 1]), sa).is_err());
        assert!(encode_dummy_policy(source, IpAddress::Ipv4([255; 4]), sa).is_err());
        assert!(validate_payload_len(0).is_err());
        assert!(validate_payload_len(1).is_ok());
        assert!(validate_payload_len(MAX_PAYLOAD).is_ok());
        assert!(validate_payload_len(MAX_PAYLOAD + 1).is_err());
    }
}
