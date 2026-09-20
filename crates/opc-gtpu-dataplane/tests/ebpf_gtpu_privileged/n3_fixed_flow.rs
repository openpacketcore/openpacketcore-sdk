use super::*;
use opc_gtpu_dataplane::n3::{
    LocalN3DownlinkTnl, N3FlowMarking, N3ForwardingIntent, N3ForwardingRole, N3Qfi,
    ReceivedN3UplinkTnl,
};

// Independent literal construction: no SDK PSC/GTP-U encoder is used here.
fn gpdu(teid: u32, qfi: u8, uplink: bool, inner: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x34, 0xff];
    packet.extend_from_slice(&u16::try_from(inner.len() + 8).unwrap().to_be_bytes());
    packet.extend_from_slice(&teid.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0x85, 1, if uplink { 0x10 } else { 0 }, qfi, 0]);
    packet.extend_from_slice(inner);
    packet
}

fn entry(base: &GtpuSessionEntry, qfi: u8) -> GtpuSessionEntry {
    let context = base.context();
    GtpuSessionEntry::from_n3(
        N3ForwardingIntent::new(
            N3ForwardingRole::N3iwf,
            ReceivedN3UplinkTnl::new(context.peer_address, context.peer_teid).unwrap(),
            LocalN3DownlinkTnl::new(base.local_outer_address(), context.local_teid).unwrap(),
            N3FlowMarking::new(N3Qfi::new(qfi).unwrap(), context.bearer_mark),
        ),
        context.ms_address,
        context.link_ifindex,
        context.downlink_source_port_policy,
        context.uplink_source_port_policy,
        context.egress_dscp,
    )
    .unwrap()
}

fn group_bytes(net: &TestNet) -> [u8; GTPU_SESSION_GROUP_VALUE_LEN] {
    let pin = grouped_pin_directory(&net.pin_root, grouped_device_id());
    let map = Map::from_map_data(MapData::from_pin(pin.join(MAP_SESSION_GROUPS)).unwrap()).unwrap();
    let groups = BpfHashMap::<_, [u8; GTPU_SESSION_GROUP_ID_LEN], [u8; GTPU_SESSION_GROUP_VALUE_LEN]>::try_from(map).unwrap();
    groups.get(&grouped_group_id().to_bytes(), 0).unwrap()
}

fn uplink_inner(net: &TestNet, ipv6: bool, payload: &[u8]) -> Vec<u8> {
    if ipv6 {
        let packet = build_inner_udp_v6(UE_PAA_IPV6, REMOTE_HOST_IPV6, 5601, 53, payload);
        send_raw_ipv6_packet(&net.ue_ns, &packet);
        return forwarded_ipv6_packet(packet);
    }
    let mut packet = build_inner_udp(UE_PAA, REMOTE_HOST, 5600, 53, payload);
    let mut frame = Vec::new();
    frame.extend_from_slice(&main_link_address("ue0"));
    frame.extend_from_slice(&[2, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&0x0800_u16.to_be_bytes());
    frame.extend_from_slice(&packet);
    send_raw_gtpu_frame(&net.ue_ns, "ue1", &frame, RawChecksumMetadata::Unverified);
    packet[8] -= 1;
    packet[10..12].fill(0);
    let header: [u8; 20] = packet[..20].try_into().unwrap();
    packet[10..12].copy_from_slice(&ipv4_header_checksum(&header).to_be_bytes());
    packet
}

fn set_uplink_mark(ipv6: bool, mark: u32) {
    run(
        "tc",
        &[
            "filter",
            "replace",
            "dev",
            "ue0",
            "ingress",
            "pref",
            if ipv6 { "21" } else { "20" },
            "protocol",
            if ipv6 { "ipv6" } else { "ip" },
            "handle",
            "1",
            "flower",
            "ip_proto",
            "udp",
            "src_port",
            if ipv6 { "5601" } else { "5600" },
            "action",
            "skbedit",
            "mark",
            &format!("0x{mark:08x}"),
            "continue",
        ],
    );
}

fn receive_uplink(socket: &UdpSocket, source: IpAddr, expected: &[u8]) {
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buffer = vec![0; 65536];
    let (length, peer) = socket
        .recv_from(&mut buffer)
        .expect("installed N3 flow delivers uplink");
    assert_eq!(peer, SocketAddr::new(source, GTPU_PORT));
    assert_eq!(&buffer[..length], expected);
}

fn send_downlink(net: &TestNet, ipv6: bool, packet: &[u8]) {
    let destination = main_link_address("s2bu");
    let source = net.pgw_link_address("s2bup");
    let frame = if ipv6 {
        build_outer_ipv6_gtpu_frame(
            destination,
            source,
            PGW_IPV6,
            EPDG_S2BU_IPV6,
            packet,
            OuterIpv6Extension::None,
        )
    } else {
        build_outer_gtpu_frame(destination, source, &[], packet, true, 0)
    };
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &frame,
        RawChecksumMetadata::Unverified,
    );
}

fn capture_checksum(capture: &OwnedFd, expected: &[u8]) {
    use nix::sys::socket::{recv, MsgFlags};
    let mut frame = vec![0; 65536];
    loop {
        let length = recv(capture.as_raw_fd(), &mut frame, MsgFlags::empty())
            .expect("capture N3 IPv6 outer packet");
        let udp = ETH_HDR_LEN + 40;
        if length < udp + 8
            || frame[12..14] != 0x86dd_u16.to_be_bytes()
            || frame[ETH_HDR_LEN + 6] != IPPROTO_UDP
        {
            continue;
        }
        let end = udp + usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
        if end > length || &frame[udp + 8..end] != expected {
            continue;
        }
        assert_eq!(
            end,
            ETH_HDR_LEN + 40 + usize::from(u16::from_be_bytes([frame[18], frame[19]]))
        );
        assert_ne!(&frame[udp + 6..udp + 8], &[0, 0]);
        assert!(udp_ipv6_checksum_is_valid(
            EPDG_S2BU_IPV6.octets(),
            PGW_IPV6.octets(),
            &frame[udp..end]
        ));
        return;
    }
}

#[allow(clippy::await_holding_lock)]
pub(super) async fn qualify() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref() != Ok("1") {
        eprintln!(
            "skipping: N3 fixed-flow native qualification requires a private privileged netns"
        );
        return Ok(());
    }
    assert_ne!(
        fs::read_link("/proc/self/ns/net")?,
        fs::read_link("/proc/1/ns/net")?
    );
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    for cross in [false, true] {
        let net = TestNet::provision();
        let config = EbpfGtpuDataplaneBackendConfig {
            bpffs_pin_root: net.pin_root.clone(),
            ..Default::default()
        };
        let backend = Arc::new(EbpfGtpuDataplaneBackend::with_config(config.clone()));
        let device = backend
            .create_device_with_endpoints(grouped_device_request(grouped_mtu_policy()))
            .await?;
        let legacy = initial_grouped_session(device.ifindex);
        let qfis = if cross { [9, 37] } else { [0, 63] };
        let mut entries = legacy.entries().to_vec();
        if cross {
            let mut v4 = entries[0].context().clone();
            v4.peer_address = IpAddr::V6(PGW_IPV6);
            v4.bearer_mark = GtpBearerMark::new(MARK_A);
            let mut v6 = entries[1].context().clone();
            v6.peer_address = IpAddr::V4(PGW_IP);
            v6.bearer_mark = GtpBearerMark::new(MARK_A);
            entries = vec![
                GtpuSessionEntry::new(v4, IpAddr::V6(EPDG_S2BU_IPV6))?,
                GtpuSessionEntry::new(v6, IpAddr::V4(EPDG_S2BU_IP))?,
            ];
        }
        let desired = GtpuSessionGroup::new(
            legacy.id(),
            legacy.device_id(),
            entries
                .iter()
                .zip(qfis)
                .map(|(base, qfi)| entry(base, qfi))
                .collect(),
        )?;
        let (namespace, stale) = reconcile_fresh_grouped(backend.clone(), desired.clone()).await?;
        assert_eq!(
            backend
                .n3_fixed_flow_capability(grouped_attachment(&device))
                .await?,
            GtpuCapability::Available
        );
        assert_eq!(
            backend.n3_forwarding_capability(N3ForwardingRole::N3iwf),
            GtpuCapability::Missing
        );
        let before = group_bytes(&net);
        let record = GtpuSessionGroupRecord::decode(&before).expect("installed atomic N3 record");
        assert_eq!(record.generation().get(), 1);
        for (family, qfi) in [
            (opc_gtpu_ebpf_common::GtpuSessionIpFamily::Ipv4, qfis[0]),
            (opc_gtpu_ebpf_common::GtpuSessionIpFamily::Ipv6, qfis[1]),
        ] {
            assert_eq!(record.entry(family).unwrap().n3_qfi(), Some(qfi));
        }
        let active = namespace
            .recover_active(backend.clone(), desired.clone())
            .await?;
        let altered = GtpuSessionGroup::new(
            desired.id(),
            desired.device_id(),
            desired
                .entries()
                .iter()
                .map(|base| entry(base, (base.n3_qfi().unwrap().get() + 1) % 64))
                .collect(),
        )?;
        assert!(namespace
            .recover_active(backend.clone(), altered)
            .await
            .is_err());
        assert_eq!(group_bytes(&net), before);
        run("ping", &["-c", "1", "-W", "1", "192.0.2.10"]);
        run("ping", &["-6", "-c", "1", "-W", "1", "2001:db8:2::10"]);
        let pgw4 = in_netns(&net.pgw_ns, || {
            UdpSocket::bind((PGW_IP, GTPU_PORT)).unwrap()
        });
        let pgw6 = in_netns(&net.pgw_ns, || {
            UdpSocket::bind((PGW_IPV6, GTPU_PORT)).unwrap()
        });
        let ue4 = in_netns(&net.ue_ns, || UdpSocket::bind((UE_PAA, 5600)).unwrap());
        let ue6 = in_netns(&net.ue_ns, || UdpSocket::bind((UE_PAA_IPV6, 5601)).unwrap());
        let capture = packet_capture_socket(&net.pgw_ns);
        for (index, installed) in desired.entries().iter().enumerate() {
            let inner6 = index == 1;
            let outer6 = installed.local_outer_address().is_ipv6();
            let qfi = qfis[index];
            let peer = if outer6 { &pgw6 } else { &pgw4 };
            let ue = if inner6 { &ue6 } else { &ue4 };
            let mark = installed
                .context()
                .bearer_mark
                .map_or(0, GtpBearerMark::get);
            set_uplink_mark(inner6, mark);
            let inner = uplink_inner(&net, inner6, b"n3-fixed-uplink");
            let expected = gpdu(installed.context().peer_teid.get(), qfi, true, &inner);
            receive_uplink(peer, installed.local_outer_address(), &expected);
            if outer6 {
                capture_checksum(&capture, &expected);
            }
            set_uplink_mark(inner6, UNKNOWN_MARK);
            uplink_inner(&net, inner6, b"n3-wrong-mark");
            expect_no_datagram(peer);
            set_uplink_mark(inner6, mark);
            let downlink_inner = if inner6 {
                build_inner_udp_v6(
                    REMOTE_HOST_IPV6,
                    UE_PAA_IPV6,
                    53,
                    5601,
                    b"n3-fixed-downlink",
                )
            } else {
                build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5600, b"n3-fixed-downlink")
            };
            let remote = if inner6 {
                IpAddr::V6(REMOTE_HOST_IPV6)
            } else {
                IpAddr::V4(REMOTE_HOST)
            };
            let local_teid = installed.context().local_teid.get();
            let valid = gpdu(local_teid, qfi, false, &downlink_inner);
            net.require_forward_mark(mark);
            send_downlink(&net, outer6, &valid);
            receive_grouped_downlink(ue, SocketAddr::new(remote, 53), b"n3-fixed-downlink");
            let mut rqi = valid.clone();
            rqi[14] |= 0x40;
            send_downlink(&net, outer6, &rqi);
            receive_grouped_downlink(ue, SocketAddr::new(remote, 53), b"n3-fixed-downlink");
            let mut ppi = valid.clone();
            ppi[12] = 2;
            ppi[14] |= 0x80;
            ppi.splice(15..16, [7, 0, 0, 0, 0]);
            let ppi_length = u16::try_from(ppi.len() - 8).unwrap();
            ppi[2..4].copy_from_slice(&ppi_length.to_be_bytes());
            send_downlink(&net, outer6, &ppi);
            receive_grouped_downlink(ue, SocketAddr::new(remote, 53), b"n3-fixed-downlink");
            // Optional unknown extensions may precede or follow the PSC.
            for before in [true, false] {
                let mut optional = valid.clone();
                if before {
                    optional[11] = 0x20;
                    optional.splice(12..12, [1, 0xa5, 0x5a, 0x85]);
                } else {
                    optional[15] = 0x20;
                    optional.splice(16..16, [1, 0xa5, 0x5a, 0]);
                }
                let length = u16::try_from(optional.len() - 8).unwrap();
                optional[2..4].copy_from_slice(&length.to_be_bytes());
                send_downlink(&net, outer6, &optional);
                receive_grouped_downlink(ue, SocketAddr::new(remote, 53), b"n3-fixed-downlink");
            }
            let mut bad = vec![
                build_gpdu(local_teid, None, &downlink_inner),
                gpdu(local_teid, (qfi + 1) % 64, false, &downlink_inner),
                gpdu(local_teid, qfi, true, &downlink_inner),
            ];
            for bit in [2, 4, 8] {
                let mut b = valid.clone();
                b[13] |= bit;
                bad.push(b);
            }
            let mut duplicate = valid.clone();
            duplicate[15] = 0x85;
            duplicate.splice(16..16, [1, 0, qfi, 0]);
            let duplicate_length = u16::try_from(duplicate.len() - 8).unwrap();
            duplicate[2..4].copy_from_slice(&duplicate_length.to_be_bytes());
            bad.push(duplicate);
            for packet in bad {
                send_downlink(&net, outer6, &packet);
            }
            expect_no_datagram(ue);
            net.allow_all_forward_marks();
            // Exact and one-byte-over boundaries include the eight PSC bytes.
            let inner_header = if inner6 { 48 } else { 28 };
            let overhead = if outer6 { 64 } else { 44 };
            let payload = vec![0x5a; 1500 - overhead - inner_header];
            let exact = uplink_inner(&net, inner6, &payload);
            let expected = gpdu(installed.context().peer_teid.get(), qfi, true, &exact);
            receive_uplink(peer, installed.local_outer_address(), &expected);
            if outer6 {
                capture_checksum(&capture, &expected);
            }
            let count = backend
                .datapath_snapshot(&device)
                .await?
                .counters
                .uplink_mtu_rejected;
            uplink_inner(&net, inner6, &vec![0x5a; payload.len() + 1]);
            expect_no_datagram(peer);
            assert_eq!(
                backend
                    .datapath_snapshot(&device)
                    .await?
                    .counters
                    .uplink_mtu_rejected,
                count + 1
            );
        }
        assert_eq!(group_bytes(&net), before);
        // New loader, same protected namespace: adoption must preserve the
        // complete N3 desired graph and QFI, not reconstruct ordinary GTP-U.
        drop(backend);
        let backend = Arc::new(EbpfGtpuDataplaneBackend::with_config(config));
        let adopted = backend
            .create_device_with_endpoints(grouped_device_request(grouped_mtu_policy()))
            .await?;
        assert_eq!(adopted, device);
        let recovered = namespace
            .recover_active(backend.clone(), desired.clone())
            .await?;
        assert_eq!(
            backend
                .n3_fixed_flow_capability(grouped_attachment(&adopted))
                .await?,
            GtpuCapability::Available
        );
        assert_eq!(group_bytes(&net), before);
        for (index, installed) in desired.entries().iter().enumerate() {
            let inner = uplink_inner(&net, index == 1, b"n3-after-adoption");
            let peer = if installed.local_outer_address().is_ipv6() {
                &pgw6
            } else {
                &pgw4
            };
            let expected = gpdu(
                installed.context().peer_teid.get(),
                qfis[index],
                true,
                &inner,
            );
            receive_uplink(peer, installed.local_outer_address(), &expected);
        }
        let _retired = namespace
            .retire(backend.clone(), recovered, desired.clone())
            .await?;
        assert!(namespace
            .retire(backend.clone(), active, desired.clone())
            .await
            .is_err());
        assert!(namespace
            .retire(backend.clone(), stale, desired.clone())
            .await
            .is_err());
        assert!(namespace
            .reconcile_fresh(backend.clone(), desired.clone())
            .await
            .is_err());
        for (index, installed) in desired.entries().iter().enumerate() {
            let inner6 = index == 1;
            uplink_inner(&net, inner6, b"n3-after-retirement");
            let peer = if installed.local_outer_address().is_ipv6() {
                &pgw6
            } else {
                &pgw4
            };
            expect_no_datagram(peer);
            let (ue, inner) = if inner6 {
                (
                    &ue6,
                    build_inner_udp_v6(
                        REMOTE_HOST_IPV6,
                        UE_PAA_IPV6,
                        53,
                        5601,
                        b"n3-after-retirement",
                    ),
                )
            } else {
                (
                    &ue4,
                    build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5600, b"n3-after-retirement"),
                )
            };
            send_downlink(
                &net,
                installed.local_outer_address().is_ipv6(),
                &gpdu(
                    installed.context().local_teid.get(),
                    qfis[index],
                    false,
                    &inner,
                ),
            );
            expect_no_datagram(ue);
        }
        drop(namespace);
        drop(backend);
        drop(net);
    }
    eprintln!("OPC_GTPU_N3_FIXED_FLOW_PROVEN: four family combinations, PSC/QFI, marks, checksums, PMTU, exact authority, adoption and retirement verified");
    Ok(())
}
