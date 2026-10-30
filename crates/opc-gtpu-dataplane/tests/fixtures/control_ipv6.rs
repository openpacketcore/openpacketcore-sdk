//! Independent control wire contract shared by both live backend tests.

use opc_gtpu_dataplane::control_port::{
    GtpuControlDatagram, GtpuControlPort, GtpuControlPortError, GtpuControlResponseBudget,
};
use opc_proto_gtpu::{GtpuExtensionHeaderType, GtpuExtensionHeaderTypeList};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub fn receive(port: &dyn GtpuControlPort) -> GtpuControlDatagram {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(datagram) = port.try_receive_datagram(2048).unwrap() {
            return datagram;
        }
        assert!(Instant::now() < deadline, "IPv6 control receive deadline");
        std::thread::sleep(Duration::from_millis(1));
    }
}

pub fn exercise(
    port: &dyn GtpuControlPort,
    local: SocketAddr,
    peer: &UdpSocket,
    service: &UdpSocket,
) {
    let budget = GtpuControlResponseBudget::new(2048, 4).unwrap();
    let echo = [0x32, 1, 0, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0];
    let answer = [0x32, 2, 0, 6, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 14, 0];
    let mut bytes = [0_u8; 2048];
    for socket in [peer, service] {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    peer.send_to(&echo, local).unwrap();
    let event = receive(port);
    assert_eq!(event.local(), local);
    assert_eq!(event.peer(), peer.local_addr().unwrap());
    assert_eq!(event.sequence_number(), Some(0x1234));
    let plan = event.echo_response(budget).unwrap();
    assert_eq!(plan.source(), local);
    assert_eq!(plan.destination(), peer.local_addr().unwrap());
    assert_eq!(port.send_control_response(plan).unwrap(), answer.len());
    let (length, from) = peer.recv_from(&mut bytes).unwrap();
    assert_eq!(from, local);
    assert_eq!(&bytes[..length], answer);

    assert_eq!(
        port.send_echo_request(local, service.local_addr().unwrap(), 0x1234)
            .unwrap(),
        echo.len()
    );
    let (length, from) = service.recv_from(&mut bytes).unwrap();
    assert_eq!(from, local);
    assert_eq!(&bytes[..length], echo);
    service.send_to(&answer, from).unwrap();
    assert_eq!(receive(port).bytes(), answer);

    let gpdu = [
        0x30, 0xff, 0, 20, 0xde, 0xad, 0xbe, 0xef, 0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10,
        23, 0, 1, 10, 23, 0, 2,
    ];
    peer.send_to(&gpdu, local).unwrap();
    let plan = receive(port).unknown_tunnel_error(budget).unwrap();
    assert_eq!(plan.destination(), service.local_addr().unwrap());
    port.send_control_response(plan).unwrap();
    let (length, from) = service.recv_from(&mut bytes).unwrap();
    assert_eq!(from, local);
    let mut expected = vec![
        0x36, 26, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0x40, 1, 0, 0, 0, 16, 0xde, 0xad, 0xbe, 0xef, 133, 0,
        16,
    ];
    expected[13..15].copy_from_slice(&peer.local_addr().unwrap().port().to_be_bytes());
    let SocketAddr::V6(local) = local else {
        panic!("IPv6 fixture required")
    };
    expected.extend_from_slice(&local.ip().octets());
    assert_eq!(&bytes[..length], expected);

    let required = [0x36, 1, 0, 8, 0, 0, 0, 0, 0x12, 0x34, 0, 0x80, 1, 0, 0, 0];
    peer.send_to(&required, local).unwrap();
    let supported =
        GtpuExtensionHeaderTypeList::new(vec![GtpuExtensionHeaderType::new(0x40)]).unwrap();
    let plan = receive(port)
        .extension_notification(supported, budget)
        .unwrap();
    port.send_control_response(plan).unwrap();
    let (length, from) = service.recv_from(&mut bytes).unwrap();
    assert_eq!(from, SocketAddr::V6(local));
    assert_eq!(
        &bytes[..length],
        &[0x32, 31, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 141, 1, 0x40]
    );

    peer.send_to(&echo, local).unwrap();
    assert_eq!(
        receive(port)
            .echo_response(GtpuControlResponseBudget::new(13, 4).unwrap())
            .unwrap_err(),
        GtpuControlPortError::ResponseBudgetExceeded
    );
}
