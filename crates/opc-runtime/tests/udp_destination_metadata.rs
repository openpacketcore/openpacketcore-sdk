use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::net::Ipv6Addr;

use opc_runtime::{
    bind_udp_socket_with_destination_metadata, UdpDestinationMetadataSocket,
    UdpDestinationMetadataSupport, UdpLocalDestinationStatus,
};
use tokio::{net::UdpSocket, time::timeout};

const IO_TIMEOUT: Duration = Duration::from_secs(2);

async fn receive_with_destination(
    socket: &UdpDestinationMetadataSocket,
    buffer: &mut [u8],
) -> opc_runtime::UdpReceivedDatagram {
    timeout(IO_TIMEOUT, socket.recv_from_with_destination(buffer))
        .await
        .expect("destination-aware receive timed out")
        .expect("destination-aware receive failed")
}

async fn receive_from(socket: &UdpSocket, buffer: &mut [u8]) -> (usize, SocketAddr) {
    timeout(IO_TIMEOUT, socket.recv_from(buffer))
        .await
        .expect("UDP receive timed out")
        .expect("UDP receive failed")
}

async fn send_to_from(
    socket: &UdpDestinationMetadataSocket,
    buffer: &[u8],
    peer: SocketAddr,
    local_source: SocketAddr,
) -> io::Result<usize> {
    timeout(IO_TIMEOUT, socket.send_to_from(buffer, peer, local_source))
        .await
        .expect("source-selected UDP send timed out")
}

fn assert_udp_error(error: &io::Error, kind: io::ErrorKind, code: &str) {
    assert_eq!(error.kind(), kind);
    assert_eq!(error.to_string(), code);
}

#[tokio::test]
async fn concrete_bind_receives_and_replies_from_local_destination() {
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let listener = bind_udp_socket_with_destination_metadata(bind_addr).unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let peer = UdpSocket::bind(bind_addr).await.unwrap();
    let peer_addr = peer.local_addr().unwrap();

    peer.send_to(b"request", listener_addr).await.unwrap();

    let mut request = [0_u8; 16];
    let received = receive_with_destination(&listener, &mut request).await;
    let local_destination = received
        .local_destination()
        .socket_addr_value()
        .expect("concrete bind must have a concrete destination");

    assert_eq!(&request[..received.bytes()], b"request");
    assert_eq!(received.source(), peer_addr);
    assert_eq!(local_destination, listener_addr);
    assert_eq!(
        received.local_destination().status(),
        UdpLocalDestinationStatus::Concrete
    );

    let sent = send_to_from(&listener, b"reply", received.source(), local_destination)
        .await
        .unwrap();
    assert_eq!(sent, 5);

    let mut reply = [0_u8; 16];
    let (bytes, source) = receive_from(&peer, &mut reply).await;
    assert_eq!(&reply[..bytes], b"reply");
    assert_eq!(source, listener_addr);
    assert!(matches!(
        listener.destination_metadata_support(),
        UdpDestinationMetadataSupport::AncillaryPacketInfo
            | UdpDestinationMetadataSupport::LocalAddrOnly
    ));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn ipv4_wildcard_reply_uses_observed_secondary_loopback_destination() {
    let listener = bind_udp_socket_with_destination_metadata(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    ))
    .unwrap();
    let destination = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        listener.local_addr().unwrap().port(),
    );
    let peer = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();

    peer.send_to(b"request-v4", destination).await.unwrap();

    let mut request = [0_u8; 32];
    let received = receive_with_destination(&listener, &mut request).await;
    let observed_destination = received
        .local_destination()
        .socket_addr_value()
        .expect("Linux packet info must identify the IPv4 destination");
    assert_eq!(&request[..received.bytes()], b"request-v4");
    assert_eq!(observed_destination, destination);
    assert_eq!(
        listener.destination_metadata_support(),
        UdpDestinationMetadataSupport::AncillaryPacketInfo
    );

    let sent = send_to_from(
        &listener,
        b"reply-v4",
        received.source(),
        observed_destination,
    )
    .await
    .unwrap();
    assert_eq!(sent, 8);

    let mut reply = [0_u8; 32];
    let (bytes, source) = receive_from(&peer, &mut reply).await;
    assert_eq!(&reply[..bytes], b"reply-v4");
    assert_eq!(source, destination);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn ipv6_wildcard_reply_uses_observed_loopback_destination() {
    let listener = bind_udp_socket_with_destination_metadata(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        0,
    ))
    .unwrap();
    let destination = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        listener.local_addr().unwrap().port(),
    );
    let peer = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .await
        .unwrap();

    peer.send_to(b"request-v6", destination).await.unwrap();

    let mut request = [0_u8; 32];
    let received = receive_with_destination(&listener, &mut request).await;
    let observed_destination = received
        .local_destination()
        .socket_addr_value()
        .expect("Linux packet info must identify the IPv6 destination");
    assert_eq!(&request[..received.bytes()], b"request-v6");
    assert_eq!(observed_destination.ip(), destination.ip());
    assert_eq!(observed_destination.port(), destination.port());

    let sent = send_to_from(
        &listener,
        b"reply-v6",
        received.source(),
        observed_destination,
    )
    .await
    .unwrap();
    assert_eq!(sent, 8);

    let mut reply = [0_u8; 32];
    let (bytes, source) = receive_from(&peer, &mut reply).await;
    assert_eq!(&reply[..bytes], b"reply-v6");
    assert_eq!(source.ip(), destination.ip());
    assert_eq!(source.port(), destination.port());
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn source_selection_rejects_family_and_port_mismatches() {
    let listener = bind_udp_socket_with_destination_metadata(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    ))
    .unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let v4_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let v4_source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_port);
    let v6_peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);
    let v6_source = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), local_port);
    let wrong_port = if local_port == u16::MAX {
        local_port - 1
    } else {
        local_port + 1
    };

    let wrong_peer_family = send_to_from(&listener, b"reply", v6_peer, v4_source)
        .await
        .unwrap_err();
    assert_udp_error(
        &wrong_peer_family,
        io::ErrorKind::InvalidInput,
        "udp_source_family_mismatch",
    );

    let wrong_source_family = send_to_from(&listener, b"reply", v4_peer, v6_source)
        .await
        .unwrap_err();
    assert_udp_error(
        &wrong_source_family,
        io::ErrorKind::InvalidInput,
        "udp_source_family_mismatch",
    );

    let wrong_source_port = send_to_from(
        &listener,
        b"reply",
        v4_peer,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), wrong_port),
    )
    .await
    .unwrap_err();
    assert_udp_error(
        &wrong_source_port,
        io::ErrorKind::InvalidInput,
        "udp_source_port_mismatch",
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn ipv4_source_selection_rejects_unsafe_and_unavailable_addresses() {
    let listener = bind_udp_socket_with_destination_metadata(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    ))
    .unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);

    for (invalid_ip, expected_code) in [
        (Ipv4Addr::UNSPECIFIED, "udp_source_unspecified"),
        (Ipv4Addr::new(224, 0, 0, 1), "udp_source_multicast"),
        (Ipv4Addr::BROADCAST, "udp_source_broadcast"),
    ] {
        let error = send_to_from(
            &listener,
            b"reply",
            peer,
            SocketAddr::new(IpAddr::V4(invalid_ip), local_port),
        )
        .await
        .unwrap_err();
        assert_udp_error(&error, io::ErrorKind::InvalidInput, expected_code);
    }

    let unavailable = send_to_from(
        &listener,
        b"reply",
        peer,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 123)), local_port),
    )
    .await
    .unwrap_err();
    assert_udp_error(
        &unavailable,
        io::ErrorKind::AddrNotAvailable,
        "udp_source_not_local",
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn ipv6_source_selection_rejects_unsafe_and_unavailable_addresses() {
    let listener = bind_udp_socket_with_destination_metadata(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        0,
    ))
    .unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);

    for (invalid_ip, expected_code) in [
        (Ipv6Addr::UNSPECIFIED, "udp_source_unspecified"),
        (
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            "udp_source_multicast",
        ),
    ] {
        let error = send_to_from(
            &listener,
            b"reply",
            peer,
            SocketAddr::new(IpAddr::V6(invalid_ip), local_port),
        )
        .await
        .unwrap_err();
        assert_udp_error(&error, io::ErrorKind::InvalidInput, expected_code);
    }

    let missing_scope = send_to_from(
        &listener,
        b"reply",
        peer,
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            local_port,
        ),
    )
    .await
    .unwrap_err();
    assert_udp_error(
        &missing_scope,
        io::ErrorKind::InvalidInput,
        "udp_source_scope_required",
    );

    let unavailable = send_to_from(
        &listener,
        b"reply",
        peer,
        SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 123)),
            local_port,
        ),
    )
    .await
    .unwrap_err();
    assert_udp_error(
        &unavailable,
        io::ErrorKind::AddrNotAvailable,
        "udp_source_not_local",
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn concrete_bind_rejects_a_different_local_source() {
    let listener = bind_udp_socket_with_destination_metadata(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
    ))
    .unwrap();
    let local_port = listener.local_addr().unwrap().port();
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let different_loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), local_port);

    let error = send_to_from(&listener, b"reply", peer, different_loopback)
        .await
        .unwrap_err();

    assert_udp_error(
        &error,
        io::ErrorKind::AddrNotAvailable,
        "udp_source_bound_address_mismatch",
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[tokio::test]
async fn source_selected_send_is_bounded_and_supports_empty_datagrams() {
    let listener = bind_udp_socket_with_destination_metadata(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    ))
    .unwrap();
    let local_source = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        listener.local_addr().unwrap().port(),
    );
    let peer = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();

    let sent = send_to_from(&listener, &[], peer.local_addr().unwrap(), local_source)
        .await
        .unwrap();
    assert_eq!(sent, 0);

    let mut empty = [0_u8; 1];
    let (bytes, source) = receive_from(&peer, &mut empty).await;
    assert_eq!(bytes, 0);
    assert_eq!(source, local_source);

    let maximum = vec![0_u8; 65_507];
    let sent = send_to_from(
        &listener,
        &maximum,
        peer.local_addr().unwrap(),
        local_source,
    )
    .await
    .unwrap();
    assert_eq!(sent, maximum.len());

    let mut maximum_received = vec![0_u8; maximum.len()];
    let (bytes, source) = receive_from(&peer, &mut maximum_received).await;
    assert_eq!(bytes, maximum.len());
    assert_eq!(source, local_source);

    let oversized = vec![0_u8; 65_508];
    let error = send_to_from(
        &listener,
        &oversized,
        peer.local_addr().unwrap(),
        local_source,
    )
    .await
    .unwrap_err();
    assert_udp_error(&error, io::ErrorKind::InvalidInput, "udp_payload_too_large");
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
#[tokio::test]
async fn wildcard_source_selection_is_explicitly_unsupported_without_packet_info() {
    let listener = bind_udp_socket_with_destination_metadata(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        0,
    ))
    .unwrap();
    let peer = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .unwrap();
    let local_source = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        listener.local_addr().unwrap().port(),
    );

    let error = send_to_from(
        &listener,
        b"reply",
        peer.local_addr().unwrap(),
        local_source,
    )
    .await
    .unwrap_err();

    assert_udp_error(
        &error,
        io::ErrorKind::Unsupported,
        "udp_source_selection_unsupported",
    );
}
