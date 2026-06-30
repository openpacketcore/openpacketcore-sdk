use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use opc_runtime::{
    bind_udp_socket_with_destination_metadata, UdpDestinationMetadataSupport,
    UdpLocalDestinationStatus,
};
use tokio::net::UdpSocket;

#[tokio::test]
async fn concrete_bind_reports_local_destination_metadata() {
    let bind_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let listener = bind_udp_socket_with_destination_metadata(bind_addr).unwrap();
    let listener_addr = listener.local_addr().unwrap();
    let sender = UdpSocket::bind(bind_addr).await.unwrap();
    let sender_addr = sender.local_addr().unwrap();

    sender.send_to(b"ike", listener_addr).await.unwrap();

    let mut buffer = [0_u8; 16];
    let received = listener
        .recv_from_with_destination(&mut buffer)
        .await
        .unwrap();

    assert_eq!(received.bytes(), 3);
    assert_eq!(&buffer[..received.bytes()], b"ike");
    assert_eq!(received.source(), sender_addr);
    assert_eq!(
        received.local_destination().socket_addr_value(),
        Some(listener_addr)
    );
    assert_eq!(
        received.local_destination().status(),
        UdpLocalDestinationStatus::Concrete
    );
    assert!(matches!(
        listener.destination_metadata_support(),
        UdpDestinationMetadataSupport::AncillaryPacketInfo
            | UdpDestinationMetadataSupport::LocalAddrOnly
    ));
}
