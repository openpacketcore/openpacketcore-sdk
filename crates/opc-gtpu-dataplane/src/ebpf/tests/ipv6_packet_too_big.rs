//! Ordinary inner-IPv6 in-tunnel Packet Too Big contracts (RFC 4443).

use super::*;
use crate::control_port::GtpuControlDatagram;
use crate::ebpf::reassembled_downlink::{
    process_downlink_datagram, DownlinkAuthorityScope, ProcessedDownlink,
};
use opc_gtpu_ebpf_common::internet_checksum;

const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const PREFIX: &str = "2001:db8:45:1::";
const DESTINATION: &str = "2001:db8:45:1::abcd";
const SOURCE: &str = "2001:db8:ffff::8";

fn ipv6_context(mark: Option<u32>) -> GtpPdpContext {
    let mut context = match mark {
        Some(mark) => marked_context(mark, 0x1000_0002, 0x2000_0002),
        None => context(),
    };
    context.ms_address = IpAddr::V6(PREFIX.parse().unwrap());
    context.downlink_inner_mtu = crate::GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(1_300);
    context
}

/// An independently formed IPv6/UDP packet, including the UDP checksum.
fn invoking(total: usize) -> Vec<u8> {
    let payload_length = u16::try_from(total - 40).unwrap();
    let mut packet = vec![0x5a; total];
    packet[..4].copy_from_slice(&[0x60, 0, 0, 0]);
    packet[4..6].copy_from_slice(&payload_length.to_be_bytes());
    packet[6..8].copy_from_slice(&[17, 64]);
    packet[8..24].copy_from_slice(&SOURCE.parse::<Ipv6Addr>().unwrap().octets());
    packet[24..40].copy_from_slice(&DESTINATION.parse::<Ipv6Addr>().unwrap().octets());
    packet[40..42].copy_from_slice(&53_u16.to_be_bytes());
    packet[42..44].copy_from_slice(&5_060_u16.to_be_bytes());
    packet[44..46].copy_from_slice(&payload_length.to_be_bytes());
    packet[46..48].fill(0);
    let mut checksum = packet[8..40].to_vec();
    checksum.extend_from_slice(&u32::from(payload_length).to_be_bytes());
    checksum.extend_from_slice(&[0, 0, 0, 17]);
    checksum.extend_from_slice(&packet[40..]);
    let value = match internet_checksum(&checksum) {
        0 => u16::MAX,
        value => value,
    };
    packet[46..48].copy_from_slice(&value.to_be_bytes());
    packet
}

fn process_ipv6(runtime: &FakeRuntime, context: &GtpPdpContext, inner: &[u8]) -> ProcessedDownlink {
    let mut gpdu = vec![0x30, 0xff];
    gpdu.extend_from_slice(&u16::try_from(inner.len()).unwrap().to_be_bytes());
    gpdu.extend_from_slice(&context.local_teid.get().to_be_bytes());
    gpdu.extend_from_slice(inner);
    process_downlink_datagram(
        runtime,
        DownlinkAuthorityScope {
            ifindex: S2BU_IFINDEX,
            grouped_config: None,
            ordinary_local_ipv4: Some(LOCAL),
        },
        GtpuControlDatagram::received(
            gpdu.into(),
            crate::DownlinkOuterProvenance::new(PEER, LOCAL, S2BU_IFINDEX, 2_152).unwrap(),
            Arc::new(()),
        ),
        &mut crate::GtpuDownlinkCounters::default(),
    )
}

#[tokio::test]
async fn ordinary_ipv6_packet_too_big_preserves_mtu_and_uses_the_default_bearer() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let default = ipv6_context(None);
    backend.install_pdp_context(default.clone()).await.unwrap();
    runtime
        .state()
        .traffic_observation_gate
        .insert(S2BU_IFINDEX, 3);
    runtime.state().grouped_map_ready.insert(S2BU_IFINDEX);

    for mark in [None, Some(7)] {
        let context = ipv6_context(mark);
        if mark.is_some() {
            backend.install_pdp_context(context.clone()).await.unwrap();
        }
        let selector = crate::PdpContextSelector::LocalTeid(
            crate::PdpContextLocalTeidSelector::from_context(&context).unwrap(),
        );
        assert_eq!(
            backend.read_pdp_context(selector).await.unwrap(),
            crate::PdpContextReadback::Present(context.clone()),
            "readback must retain the exact IPv6 MTU opt-in"
        );

        let fitting = invoking(1_300);
        let ProcessedDownlink::Event(crate::GtpuDownlinkEvent::Decapsulated(packet)) =
            process_ipv6(&runtime, &context, &fitting)
        else {
            panic!("the exact-MTU IPv6 packet must be forwarded");
        };
        assert_eq!(packet.inner_packet(), fitting);
        assert_eq!(packet.family(), GtpAddressFamily::Ipv6);
        assert_eq!(packet.bearer_mark(), context.bearer_mark);

        let oversized = invoking(1_400);
        let ProcessedDownlink::PacketTooBig(plan) = process_ipv6(&runtime, &context, &oversized)
        else {
            panic!("an oversized IPv6 packet must become an in-tunnel PTB plan");
        };
        assert_eq!(plan.mtu(), 1_300);
        assert_eq!(plan.family(), GtpAddressFamily::Ipv6);
        assert_eq!(plan.session(), context.local_teid.get().to_be_bytes());
        let (gpdu, local, peer) = plan.build_uplink_gpdu().unwrap();
        assert_eq!((local, peer), (LOCAL, PEER));
        assert_eq!(&gpdu[..4], &[0x30, 0xff, 0x05, 0x00]);
        assert_eq!(&gpdu[4..8], &default.peer_teid.get().to_be_bytes());
        let error = &gpdu[8..];
        // RFC 4443 sections 2.3, 2.4(c), and 3.2: exact type, MTU,
        // maximum quote, addresses, and IPv6 pseudo-header checksum.
        assert_eq!(error.len(), 1_280);
        assert_eq!(&error[..8], &[0x60, 0, 0, 0, 0x04, 0xd8, 58, 64]);
        assert_eq!(&error[8..24], &oversized[24..40]);
        assert_eq!(&error[24..40], &oversized[8..24]);
        assert_eq!(&error[40..42], &[2, 0]);
        assert_eq!(&error[44..48], &1_300_u32.to_be_bytes());
        assert_eq!(&error[48..], &oversized[..1_232]);
        let mut checksum = error[8..40].to_vec();
        checksum.extend_from_slice(&1_240_u32.to_be_bytes());
        checksum.extend_from_slice(&[0, 0, 0, 58]);
        checksum.extend_from_slice(&error[40..]);
        assert_eq!(internet_checksum(&checksum), 0);
    }
}

#[tokio::test]
async fn ipv6_packet_too_big_never_answers_errors_redirects_or_nonunique_sources() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let context = ipv6_context(None);
    backend.install_pdp_context(context.clone()).await.unwrap();
    runtime
        .state()
        .traffic_observation_gate
        .insert(S2BU_IFINDEX, 3);
    runtime.state().grouped_map_ready.insert(S2BU_IFINDEX);
    let permits = |packet: &[u8]| {
        let ProcessedDownlink::PacketTooBig(plan) = process_ipv6(&runtime, &context, packet) else {
            panic!("oversized packet must not be decapsulated");
        };
        plan.build_uplink_gpdu().is_some()
    };
    for source in ["::", "::1", "ff02::1", "2001:db8:ffff::"] {
        let mut packet = invoking(1_400);
        packet[8..24].copy_from_slice(&source.parse::<Ipv6Addr>().unwrap().octets());
        assert!(!permits(&packet), "must not answer {source}");
    }
    for extension in [None, Some(0), Some(43), Some(60), Some(51), Some(44)] {
        for kind in [1, 2, 3, 4, 127, 128, 129, 137] {
            let mut packet = invoking(1_400);
            packet[6] = extension.unwrap_or(58);
            let offset = if extension.is_some() {
                packet[40..48].fill(0);
                packet[40] = 58;
                48
            } else {
                40
            };
            packet[offset] = kind;
            packet[offset + 1..offset + 4].fill(0);
            let mut pseudo = packet[8..40].to_vec();
            pseudo.extend_from_slice(&u32::try_from(packet.len() - offset).unwrap().to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 58]);
            pseudo.extend_from_slice(&packet[offset..]);
            packet[offset + 2..offset + 4]
                .copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
            assert_eq!(
                permits(&packet),
                matches!(kind, 128 | 129),
                "extension {extension:?}, kind {kind}"
            );
        }
    }
    let mut fragment = invoking(1_400);
    fragment[6] = 44;
    fragment[40..48].copy_from_slice(&[17, 0, 0, 8, 0, 0, 0, 7]);
    assert!(!permits(&fragment), "non-initial fragment is unsendable");
    let mut truncated_chain = invoking(1_400);
    truncated_chain[6] = 60;
    truncated_chain[40..42].copy_from_slice(&[58, 255]);
    assert!(
        !permits(&truncated_chain),
        "truncated extension is unsendable"
    );
    let mut excessive_chain = invoking(1_400);
    excessive_chain[6] = 60;
    for index in 0..17 {
        excessive_chain[40 + index * 8..48 + index * 8].fill(0);
        excessive_chain[40 + index * 8] = 60;
    }
    assert!(
        !permits(&excessive_chain),
        "unresolved extension chain is unsendable"
    );
}

#[tokio::test]
async fn ipv6_packet_too_big_requires_the_default_bearers_own_active_authority() {
    for fault in [
        "missing",
        "no-index",
        "pending",
        "selected-port",
        "stale-generation",
    ] {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let dedicated = ipv6_context(Some(7));
        backend
            .install_pdp_context(dedicated.clone())
            .await
            .unwrap();
        let mut default = ipv6_context(None);
        if fault != "missing" {
            if fault == "selected-port" {
                default.downlink_inner_mtu = None;
                default.uplink_source_port_policy =
                    crate::GtpuUplinkSourcePortPolicy::Selected(40_000);
            }
            backend.install_pdp_context(default).await.unwrap();
            let mut state = runtime.state();
            let key = state
                .session_uplink_index
                .keys()
                .find(|(_, key)| key[20..24] == [0; 4])
                .copied()
                .unwrap();
            let reference = state.session_uplink_index[&key];
            let reference = GtpuSessionGroupRef::decode(&reference).unwrap();
            match fault {
                "no-index" => {
                    state.session_uplink_index.remove(&key);
                }
                "pending" => {
                    state
                        .session_groups
                        .get_mut(&(S2BU_IFINDEX, reference.group_id().to_bytes()))
                        .unwrap()[1] = GtpuSessionGroupPhase::Pending as u8;
                }
                "stale-generation" => {
                    state
                        .session_groups
                        .get_mut(&(S2BU_IFINDEX, reference.group_id().to_bytes()))
                        .unwrap()[11] = 2;
                }
                _ => {}
            }
        }
        runtime
            .state()
            .traffic_observation_gate
            .insert(S2BU_IFINDEX, 3);
        runtime.state().grouped_map_ready.insert(S2BU_IFINDEX);
        let ProcessedDownlink::PacketTooBig(plan) =
            process_ipv6(&runtime, &dedicated, &invoking(1_400))
        else {
            panic!("oversized dedicated packet must remain a PTB refusal");
        };
        assert!(plan.build_uplink_gpdu().is_none(), "default fault {fault}");
    }
}

#[tokio::test]
async fn ipv6_packet_too_big_mtu_survives_restart_and_exact_removal() {
    for mark in [None, Some(7)] {
        let (backend, runtime) = backend_with_fake();
        backend.create_device(create_request()).await.unwrap();
        let desired = ipv6_context(mark);
        backend.install_pdp_context(desired.clone()).await.unwrap();
        suspend_fake_attachment(&mut runtime.state(), S2BU_IFINDEX);
        let restarted = EbpfGtpuDataplaneBackend::with_runtime(runtime.clone());
        restarted.resolve_device("s2bu").await.unwrap();
        let selector = crate::PdpContextSelector::LocalTeid(
            crate::PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
        );
        assert_eq!(
            restarted.read_pdp_context(selector.clone()).await.unwrap(),
            crate::PdpContextReadback::Present(desired.clone())
        );
        let mut wrong = desired.clone();
        wrong.downlink_inner_mtu = crate::GtpuDownlinkInnerMtu::in_tunnel_packet_too_big(1_301);
        assert!(matches!(
            restarted.remove_pdp_context_exact(wrong).await.unwrap(),
            crate::PdpContextRemovalOutcome::Conflict(_)
        ));
        assert_eq!(
            restarted.remove_pdp_context_exact(desired).await.unwrap(),
            crate::PdpContextRemovalOutcome::Removed
        );
        assert_eq!(
            restarted.read_pdp_context(selector).await.unwrap(),
            crate::PdpContextReadback::Absent
        );
    }
}

#[tokio::test]
async fn ipv6_packet_too_big_refuses_selected_uplink_port_before_publication() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let mut context = ipv6_context(None);
    context.uplink_source_port_policy = crate::GtpuUplinkSourcePortPolicy::Selected(40_000);
    assert!(matches!(
        backend.install_pdp_context(context).await,
        Err(GtpuError::UnsupportedFeature {
            feature: "downlink_inner_mtu_with_selected_uplink_source_port"
        })
    ));
    assert!(runtime.state().session_groups.is_empty());
    assert!(runtime.state().session_uplink_index.is_empty());
    assert!(runtime.state().session_downlink_index.is_empty());
}

#[tokio::test]
async fn peer_teid_zero_installs_and_round_trips_ordinary_contexts() {
    for ipv6 in [false, true] {
        for mark in [None, Some(7)] {
            let (backend, _) = backend_with_fake();
            backend.create_device(create_request()).await.unwrap();
            let mut desired = if ipv6 {
                ipv6_context(mark)
            } else {
                match mark {
                    None => context(),
                    Some(mark) => marked_context(mark, 0x1000_0002, 0x2000_0002),
                }
            };
            desired.peer_teid = crate::PeerTeid::ZERO;
            backend.install_pdp_context(desired.clone()).await.unwrap();
            let selector = crate::PdpContextSelector::LocalTeid(
                crate::PdpContextLocalTeidSelector::from_context(&desired).unwrap(),
            );
            assert_eq!(
                backend.read_pdp_context(selector.clone()).await.unwrap(),
                crate::PdpContextReadback::Present(desired.clone())
            );
            assert_eq!(
                backend.remove_pdp_context_exact(desired).await.unwrap(),
                crate::PdpContextRemovalOutcome::Removed
            );
            assert_eq!(
                backend.read_pdp_context(selector).await.unwrap(),
                crate::PdpContextReadback::Absent
            );
        }
    }
}

#[tokio::test]
async fn ipv6_packet_too_big_suppresses_errors_behind_extension_headers() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let context = ipv6_context(None);
    backend.install_pdp_context(context.clone()).await.unwrap();
    runtime.state().grouped_map_ready.insert(S2BU_IFINDEX);
    for extension in [0, 43, 60, 51, 44] {
        let mut packet = invoking(1_400);
        packet[6] = extension;
        packet[40..48].fill(0);
        packet[40] = 58;
        packet[48] = 1;
        let ProcessedDownlink::PacketTooBig(plan) = process_ipv6(&runtime, &context, &packet)
        else {
            panic!("oversized packet must not be decapsulated");
        };
        assert!(plan.build_uplink_gpdu().is_none(), "extension {extension}");
    }
}

#[tokio::test]
async fn ipv6_packet_too_big_suppresses_redirects_and_anycast_proxy_sources() {
    let (backend, runtime) = backend_with_fake();
    backend.create_device(create_request()).await.unwrap();
    let context = ipv6_context(None);
    backend.install_pdp_context(context.clone()).await.unwrap();
    runtime.state().grouped_map_ready.insert(S2BU_IFINDEX);
    for anycast in [false, true] {
        let mut packet = invoking(1_400);
        if anycast {
            packet[24..40].copy_from_slice(&PREFIX.parse::<Ipv6Addr>().unwrap().octets());
        } else {
            packet[6] = 58;
            packet[40] = 137;
        }
        let ProcessedDownlink::PacketTooBig(plan) = process_ipv6(&runtime, &context, &packet)
        else {
            panic!("oversized packet must not be decapsulated");
        };
        assert!(plan.build_uplink_gpdu().is_none(), "anycast {anycast}");
    }
}

#[test]
fn ipv6_packet_too_big_retained_schema_v6_is_not_current_authority() {
    let config = GtpuSessionDeviceConfig::new(
        opc_gtpu_ebpf_common::GtpuSessionDeviceId::new([0x42; 16]).unwrap(),
        S2BU_IFINDEX,
        Some(LOCAL.octets()),
        None,
    )
    .unwrap()
    .encode();
    assert!(matches!(
        classify_ordinary_family_authority(config, *b"OPC-GROUP-IP-v6\0"),
        Err(GtpuError::StateIndeterminate {
            operation: "ebpf_ordinary_family_authority"
        })
    ));
    assert!(
        matches!(classify_ordinary_family_authority(config, *b"OPC-GROUP-IP-v7\0"),
        Ok(OrdinaryFamilyAuthority::Initialized(actual)) if actual == config)
    );
}
