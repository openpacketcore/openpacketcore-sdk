use super::*;
use crate::control_port::GtpuControlPortError;
use crate::{GtpuDownlinkDrop, GtpuDownlinkEvent};
use std::sync::mpsc;

fn gpdu(teid: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x30, 0xff];
    bytes.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(&teid.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn inspect_response(
    transport: &CapturingTransport,
    inspect: impl FnOnce(LinuxGtpuDataplaneBackendConfig, &[u8]) -> TransportResponse + Send + 'static,
) {
    transport
        .responses
        .lock()
        .unwrap()
        .push_back(QueuedResponse::Inspect(Box::new(inspect)));
}

fn absent_in_both_families(transport: &CapturingTransport) {
    push_family_lookup(transport);
    for _ in 0..4 {
        push_absent(transport);
    }
}

fn read_families(transport: &CapturingTransport) -> Vec<u8> {
    transport
        .requests()
        .iter()
        .filter(|request| request.operation == "read_pdp_context")
        .map(|request| {
            attr_u8(
                &netlink_body(&request.request)[GENERIC_NETLINK_HEADER_LEN..],
                GTPA_FAMILY,
            )
        })
        .collect()
}

#[tokio::test]
async fn linux_control_port_cross_family_teid_checks_both_tables() {
    for ipv6_context in [false, true] {
        let transport = control_transport();
        let address = Ipv4Addr::new(127, 37, 5, 1 + u8::from(ipv6_context));
        let (backend, device) = real_control_fixture_with_transport(address, transport.clone());
        let port = backend.open_gtpu_control_port(&device).await.unwrap();
        let mut context = pdp_context();
        context.link_ifindex = device.ifindex;
        if ipv6_context {
            context.ms_address = "2001:db8:23:1::".parse().unwrap();
        }
        let present_family = if ipv6_context { AF_INET6 } else { AF_INET };
        push_family_lookup(&transport);
        for _ in 0..4 {
            let context = context.clone();
            inspect_response(&transport, move |_, request| {
                let family = attr_u8(
                    &netlink_body(request)[GENERIC_NETLINK_HEADER_LEN..],
                    GTPA_FAMILY,
                );
                assert!(matches!(family, AF_INET | AF_INET6));
                if family == present_family {
                    Ok(Some(pdp_response(&context, true)))
                } else {
                    Err(GtpuError::NotFound)
                }
            });
        }
        let mut inner = vec![0; if ipv6_context { 20 } else { 40 }];
        inner[0] = if ipv6_context { 0x45 } else { 0x60 };
        let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        peer.send_to(
            &gpdu(context.local_teid.get(), &inner),
            (address, GTPU_PORT),
        )
        .unwrap();
        let event = port.try_receive_downlink(64).unwrap().unwrap();
        let families = read_families(&transport);
        assert!(
            matches!(
                event,
                GtpuDownlinkEvent::Dropped(GtpuDownlinkDrop::DestinationMismatch)
            ),
            "live family {present_family} TEID was classified as {event:?}; reads: {families:?}"
        );
        assert_eq!(families, [AF_INET, AF_INET, AF_INET6, AF_INET6]);
    }
}

#[tokio::test]
async fn linux_control_port_unstructured_tpdus_preserve_validated_bytes() {
    for (index, payload) in [vec![1], vec![1; 20]].into_iter().enumerate() {
        let transport = control_transport();
        let address = Ipv4Addr::new(127, 37, 4, 2 + u8::try_from(index).unwrap());
        let (backend, device) = real_control_fixture_with_transport(address, transport.clone());
        let port = backend.open_gtpu_control_port(&device).await.unwrap();
        absent_in_both_families(&transport);
        let bytes = gpdu(0x0102_0304, &payload);
        let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        peer.send_to(&bytes, (address, GTPU_PORT)).unwrap();
        let event = port.try_receive_downlink(64).unwrap().unwrap();
        let GtpuDownlinkEvent::UnknownTunnel(datagram) = event else {
            panic!("nonempty unstructured T-PDU was classified as {event:?}");
        };
        assert_eq!(datagram.bytes(), bytes);
        assert_eq!(
            read_families(&transport),
            [AF_INET, AF_INET, AF_INET6, AF_INET6]
        );
        assert!(port.try_receive_downlink(64).unwrap().is_none());
    }
}

#[tokio::test]
async fn linux_control_port_registry_contention_after_receive_is_not_busy() {
    let transport = control_transport();
    let address = Ipv4Addr::new(127, 37, 4, 4);
    let (backend, device) = real_control_fixture_with_transport(address, transport.clone());
    let port = backend.open_gtpu_control_port(&device).await.unwrap();
    let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let plan = receive_control_echo_plan(port.as_ref(), &peer, address);
    absent_in_both_families(&transport);
    let (entered, received) = mpsc::sync_channel(1);
    let latch = Arc::new(ResponseLatch::new());
    let mut release = ResponseLatchReleaseGuard::new(latch.clone());
    *backend.inner.control_ports.lock().unwrap()[&device.ifindex]
        .after_receive
        .lock()
        .unwrap() = Some(Arc::new(move || {
        entered.send(()).unwrap();
        latch.wait();
    }));
    let bytes = gpdu(0x0102_0304, &[0x45; 20]);
    peer.send_to(&bytes, (address, GTPU_PORT)).unwrap();
    let (done, result) = mpsc::sync_channel(1);
    let receiving = Arc::clone(&port);
    let worker = std::thread::spawn(move || done.send(receiving.try_receive_downlink(64)).unwrap());
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    let registry = backend.inner.device_sockets.lock().unwrap();
    let send = port.send_control_response(plan);
    let echo = [0x32, 1, 0, 4, 0, 0, 0, 0, 1, 2, 0, 0];
    peer.send_to(&echo, (address, GTPU_PORT)).unwrap();
    let busy = port.try_receive_downlink(64);
    release.release_now();
    let event = result.recv_timeout(Duration::from_secs(2));
    drop(registry);
    worker.join().unwrap();
    let event = event
        .unwrap()
        .expect("a dequeued datagram must not return Busy")
        .unwrap();
    let GtpuDownlinkEvent::UnknownTunnel(datagram) = event else {
        panic!("{event:?}")
    };
    assert_eq!(datagram.bytes(), bytes);
    assert_eq!(
        send,
        Ok(14),
        "receive contention must not consume an affine plan"
    );
    assert!(matches!(busy, Err(GtpuControlPortError::Busy)));
    assert_eq!(
        port.try_receive_datagram(64).unwrap().unwrap().bytes(),
        echo
    );
    assert!(port.try_receive_datagram(64).unwrap().is_none());
    let mut response = [0; 64];
    let (length, source) = peer.recv_from(&mut response).unwrap();
    assert_eq!(source, (address, GTPU_PORT).into());
    assert_eq!(
        &response[..length],
        &[0x32, 2, 0, 6, 0, 0, 0, 0, 0x91, 0x73, 0, 0, 14, 0]
    );
}

#[tokio::test]
async fn linux_control_port_delayed_readback_never_waits_for_a_reply() {
    for delayed_family_lookup in [false, true] {
        let transport = control_transport();
        let address = Ipv4Addr::new(127, 37, 5, 3 + u8::from(delayed_family_lookup));
        let (mut backend, device) = real_control_fixture_with_transport(address, transport.clone());
        Arc::get_mut(&mut backend.inner).unwrap().config =
            LinuxGtpuDataplaneBackendConfig::default();
        let port = backend.open_gtpu_control_port(&device).await.unwrap();
        if !delayed_family_lookup {
            push_family_lookup(&transport);
        }
        let (entered, received) = mpsc::sync_channel(1);
        let latch = Arc::new(ResponseLatch::new());
        let mut release = ResponseLatchReleaseGuard::new(latch.clone());
        inspect_response(&transport, move |config, _| {
            entered.send(config).unwrap();
            if config.receive_attempts != 1 || !config.retry_delay.is_zero() {
                latch.wait();
            }
            Err(GtpuError::io(
                "read_pdp_context",
                io::Error::from(io::ErrorKind::WouldBlock),
            ))
        });
        let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        peer.send_to(&gpdu(0x0102_0304, &[0x45; 20]), (address, GTPU_PORT))
            .unwrap();
        let (done, result) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || done.send(port.try_receive_downlink(64)).unwrap());
        let config = received.recv_timeout(Duration::from_secs(2)).unwrap();
        let immediate = result.recv_timeout(Duration::from_secs(2));
        release.release_now();
        worker.join().unwrap();
        assert!(
            immediate.is_ok(),
            "try-call waited for a delayed reply with {config:?}"
        );
        assert_eq!(config.receive_attempts, 1);
        assert!(config.retry_delay.is_zero());
        assert!(matches!(
            immediate.unwrap().unwrap(),
            Some(GtpuDownlinkEvent::Dropped(
                GtpuDownlinkDrop::StateUnavailable
            ))
        ));
        assert_eq!(
            transport.requests().len(),
            if delayed_family_lookup { 1 } else { 2 }
        );
    }
}

#[tokio::test]
async fn linux_control_port_binding_loss_after_dequeue_is_a_consumed_drop() {
    let transport = control_transport();
    let address = Ipv4Addr::new(127, 37, 5, 5);
    let (backend, device) = real_control_fixture_with_transport(address, transport.clone());
    let port = backend.open_gtpu_control_port(&device).await.unwrap();
    absent_in_both_families(&transport);
    transport.push_ifindex_response(IfindexResponse::Found(device.ifindex));
    transport.push_ifindex_response(IfindexResponse::NotFound);
    let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    peer.send_to(&gpdu(0x0102_0304, &[0x45; 20]), (address, GTPU_PORT))
        .unwrap();
    assert!(matches!(
        port.try_receive_downlink(64).unwrap(),
        Some(GtpuDownlinkEvent::Dropped(
            GtpuDownlinkDrop::StateUnavailable
        ))
    ));
    assert_eq!(
        read_families(&transport),
        [AF_INET, AF_INET, AF_INET6, AF_INET6]
    );
    assert!(matches!(
        port.try_receive_downlink(64),
        Err(GtpuControlPortError::Unavailable)
    ));
}

#[tokio::test]
async fn linux_control_port_readback_does_not_hold_the_socket_registry() {
    let transport = control_transport();
    let address = Ipv4Addr::new(127, 37, 4, 6);
    let second_address = Ipv4Addr::new(127, 37, 4, 7);
    let (backend, device) = real_control_fixture_with_transport(address, transport.clone());
    let first = backend.open_gtpu_control_port(&device).await.unwrap();
    let second_device = GtpDevice {
        name: "gtp1".into(),
        ifindex: 43,
    };
    backend
        .retain_device_socket(
            &second_device,
            real_control_socket(&second_device.name, second_address),
        )
        .unwrap();
    transport.push_ifindex_response(IfindexResponse::Found(43));
    let second = backend
        .open_gtpu_control_port(&second_device)
        .await
        .unwrap();
    let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    for _ in 0..2 {
        transport.push_ifindex_response(IfindexResponse::Found(43));
    }
    let plan = receive_control_echo_plan(second.as_ref(), &peer, second_address);
    push_family_lookup(&transport);
    let (entered, received) = mpsc::sync_channel(1);
    let latch = Arc::new(ResponseLatch::new());
    let mut release = ResponseLatchReleaseGuard::new(latch.clone());
    inspect_response(&transport, move |_, _| {
        entered.send(()).unwrap();
        latch.wait(); // Model an in-flight observation at an exact transport boundary.
        Err(GtpuError::NotFound)
    });
    peer.send_to(&gpdu(0x0102_0304, &[0x45; 20]), (address, GTPU_PORT))
        .unwrap();
    let worker = std::thread::spawn(move || first.try_receive_downlink(64));
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    for _ in 0..4 {
        transport.push_ifindex_response(IfindexResponse::Found(43));
    }
    let send = second.send_control_response(plan);
    peer.send_to(
        &[0x32, 1, 0, 4, 0, 0, 0, 0, 1, 2, 0, 0],
        (second_address, GTPU_PORT),
    )
    .unwrap();
    let receive = second.try_receive_datagram(64);
    // Device creation/removal must not wait for another attachment's readback.
    transport.ifindex_responses.lock().unwrap().clear();
    for _ in 0..2 {
        transport.push_response(Ok(None));
        transport.push_ifindex_response(IfindexResponse::Found(44));
    }
    let (done, result) = mpsc::sync_channel(1);
    let other = backend.clone();
    let mutation = std::thread::spawn(move || {
        let mut request = CreateGtpDeviceRequest::new("gtp2");
        request.bind_address = IpAddr::V4(Ipv4Addr::new(127, 37, 4, 8));
        let outcome = other.create_device_sync(request).and_then(|device| {
            assert_eq!(device.ifindex, 44);
            other.remove_device_sync(device)
        });
        done.send(outcome).unwrap();
    });
    let progress = result.recv_timeout(Duration::from_secs(2));
    // Consume any unused synthetic name responses before the first port's
    // final identity check, even when a failing implementation skipped I/O.
    transport.ifindex_responses.lock().unwrap().clear();
    for _ in 0..3 {
        push_absent(&transport);
    }
    release.release_now();
    let first_result = worker.join().unwrap();
    mutation.join().unwrap();
    assert_eq!(
        send,
        Ok(14),
        "an affine plan must not be consumed by registry contention"
    );
    assert!(
        receive.unwrap().is_some(),
        "another attachment must receive during readback"
    );
    assert!(
        progress.is_ok(),
        "device creation/removal waited behind another attachment's readback"
    );
    progress.unwrap().unwrap();
    let mutations: Vec<_> = transport
        .requests()
        .into_iter()
        .filter_map(|request| {
            matches!(request.operation, "create_device" | "remove_device")
                .then_some(request.operation)
        })
        .collect();
    assert_eq!(mutations, ["create_device", "remove_device"]);
    assert!(matches!(
        first_result.unwrap(),
        Some(GtpuDownlinkEvent::UnknownTunnel(_))
    ));
    let mut bytes = [0; 64];
    let (length, source) = peer.recv_from(&mut bytes).unwrap();
    assert_eq!(source, (second_address, GTPU_PORT).into());
    assert_eq!(
        &bytes[..length],
        &[0x32, 2, 0, 6, 0, 0, 0, 0, 0x91, 0x73, 0, 0, 14, 0]
    );
    assert_ne!(send, Err(GtpuControlPortError::Busy));
}
