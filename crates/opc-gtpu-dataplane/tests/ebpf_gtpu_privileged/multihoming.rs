use super::*;
use opc_gtpu_dataplane::GtpuPeerSourcePolicy;

#[allow(clippy::await_holding_lock)]
pub(super) async fn exercise_multihoming() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(env::var("OPC_GTPU_RUN_PRIVILEGED").as_deref(), Ok("1"));
    let _serial = PRIVILEGED_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let net = TestNet::provision();
    let config = EbpfGtpuDataplaneBackendConfig {
        bpffs_pin_root: net.pin_root.clone(),
        ..EbpfGtpuDataplaneBackendConfig::default()
    };
    let backend = EbpfGtpuDataplaneBackend::with_config(config.clone());
    let mut request = CreateGtpDeviceRequest::new("s2bu");
    request.bind_address = IpAddr::V4(EPDG_S2BU_IP);
    let device = backend.create_device(request).await?;
    let strict = session_context(device.ifindex);
    backend.install_pdp_context(strict.clone()).await?;
    let ue = in_netns(&net.ue_ns, || UdpSocket::bind((UE_PAA, 5000)))?;
    let inner = build_inner_udp(REMOTE_HOST, UE_PAA, 53, 5000, b"alternate-peer");
    let gpdu = build_gpdu(LOCAL_TEID, None, &inner);
    let original = build_outer_gtpu_frame(
        main_link_address("s2bu"),
        net.pgw_link_address("s2bup"),
        &[],
        &gpdu,
        true,
        0,
    );
    // Establish neighbour resolution using the original, still-authorized peer.
    let mut buffer = [0; 2048];
    assert!(send_until_received(
        || send_raw_gtpu_frame(
            &net.pgw_ns,
            "s2bup",
            &original,
            RawChecksumMetadata::Unverified
        ),
        &ue,
        &mut buffer
    )
    .is_some());
    drain_datagrams(&ue);
    let mut alternate = original.clone();
    alternate[ETH_HDR_LEN + 12..ETH_HDR_LEN + 16].copy_from_slice(&[192, 0, 2, 11]);
    refresh_outer_ipv4_checksum(&mut alternate);
    refresh_outer_udp_checksum(&mut alternate);
    let before = backend.datapath_snapshot(&device).await?.counters;
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &alternate,
        RawChecksumMetadata::Unverified,
    );
    expect_no_datagram(&ue);
    assert_eq!(
        backend
            .datapath_snapshot(&device)
            .await?
            .counters
            .downlink_decapsulated,
        before.downlink_decapsulated
    );
    backend.remove_pdp_context_exact(strict.clone()).await?;
    let mut desired = strict;
    desired.downlink_peer_source_policy = GtpuPeerSourcePolicy::TeidAndLocal;
    backend.install_pdp_context(desired.clone()).await?;
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &alternate,
        RawChecksumMetadata::Unverified,
    );
    receive_raw_downlink(&ue, b"alternate-peer");
    drop(backend);
    let restarted = EbpfGtpuDataplaneBackend::with_config(config);
    let recovered = restarted.resolve_device("s2bu").await?;
    let selector = PdpContextSelector::LocalTeid(
        PdpContextLocalTeidSelector::from_context(&desired).ok_or("local selector")?,
    );
    assert_eq!(
        restarted.read_pdp_context(selector).await?,
        PdpContextReadback::Present(desired.clone())
    );
    send_raw_gtpu_frame(
        &net.pgw_ns,
        "s2bup",
        &alternate,
        RawChecksumMetadata::Unverified,
    );
    receive_raw_downlink(&ue, b"alternate-peer");
    let before = restarted
        .datapath_snapshot(&recovered)
        .await?
        .counters
        .downlink_decapsulated;
    for field in ["local", "port", "teid", "paa"] {
        let mut bad = alternate.clone();
        match field {
            "local" => bad[ETH_HDR_LEN + 19] ^= 1,
            "port" => {
                let udp = outer_udp_offset(&bad);
                bad[udp + 1] ^= 1;
            }
            "teid" => {
                let gtpu = outer_gtpu_offset(&bad);
                bad[gtpu + 7] ^= 1;
            }
            "paa" => {
                let inner = outer_gtpu_offset(&bad) + 8;
                bad[inner + 19] ^= 1;
                bad[inner + 10..inner + 12].fill(0);
                let checksum = internet_checksum(&bad[inner..inner + IPV4_MIN_HDR_LEN]);
                bad[inner + 10..inner + 12].copy_from_slice(&checksum.to_be_bytes());
            }
            _ => unreachable!(),
        }
        refresh_outer_ipv4_checksum(&mut bad);
        refresh_outer_udp_checksum(&mut bad);
        send_raw_gtpu_frame(&net.pgw_ns, "s2bup", &bad, RawChecksumMetadata::Unverified);
        expect_no_datagram(&ue);
    }
    assert_eq!(
        restarted
            .datapath_snapshot(&recovered)
            .await?
            .counters
            .downlink_decapsulated,
        before
    );
    assert_eq!(
        restarted.remove_pdp_context_exact(desired).await?,
        PdpContextRemovalOutcome::Removed
    );
    restarted.remove_device(&recovered).await?;
    eprintln!(
        "OPC_GTPU_MULTIHOMING_PROVEN strict=reject opt_in=accept restart=preserved mismatches=4"
    );
    Ok(())
}
