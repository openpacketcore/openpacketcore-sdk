//! Synthetic independent UDP peer; runs only in an explicitly private netns.

use super::*;
use crate::GtpuReassemblySocket;
use std::{
    net::{Ipv4Addr, UdpSocket},
    time::{Duration, Instant},
};

fn receive(socket: &dyn GtpuControlPort, cap: usize) -> GtpuControlDatagram {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(event) = socket.try_receive_datagram(cap).unwrap() {
            return event;
        }
        assert!(
            Instant::now() < deadline,
            "control datagram receive deadline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
#[ignore = "requires a private network namespace with loopback up"]
fn control_socket_native_preserves_tuple_budget_and_exact_socket() {
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::fs::read_link("/proc/1/ns/net").unwrap(),
        "private network namespace required"
    );
    let local = Ipv4Addr::new(127, 0, 0, 2);
    let remote = Ipv4Addr::new(127, 0, 0, 3);
    let socket = GtpuReassemblySocket::bind(local, "lo").unwrap();
    let other = GtpuReassemblySocket::bind(Ipv4Addr::new(127, 0, 0, 4), "lo").unwrap();
    let peer = UdpSocket::bind((remote, 0)).unwrap();
    let service = UdpSocket::bind((remote, 2152)).unwrap();
    for s in [&peer, &service] {
        s.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
    }
    let destination = SocketAddrV4::new(local, 2152);
    let budget = GtpuControlResponseBudget::new(1024, 4).unwrap();
    let request = [0x32, 1, 0, 4, 0, 0, 0, 0, 0xab, 0xcd, 0, 0];
    let mut reply = [0; 1024];
    assert!(socket.try_receive_datagram(1024).unwrap().is_none());
    peer.send_to(&request, destination).unwrap();
    let event = receive(&socket, 1024);
    assert_eq!(event.local(), destination);
    assert_eq!(
        std::net::SocketAddr::V4(event.peer()),
        peer.local_addr().unwrap()
    );
    assert_eq!(
        event.provenance().ingress_ifindex(),
        socket.ingress_ifindex()
    );
    assert_eq!(event.sequence_number(), Some(0xabcd));
    assert_eq!(
        socket
            .send_control_response(event.echo_response(budget).unwrap())
            .unwrap(),
        14
    );
    let (n, from) = peer.recv_from(&mut reply).unwrap();
    assert_eq!(from, std::net::SocketAddr::V4(destination));
    assert_eq!(
        &reply[..n],
        &[0x32, 2, 0, 6, 0, 0, 0, 0, 0xab, 0xcd, 0, 0, 14, 0]
    );
    // A socket replaced at the identical tuple is still a different instance.
    peer.send_to(&request, destination).unwrap();
    let retired_plan = receive(&socket, 1024).echo_response(budget).unwrap();
    drop(socket);
    let socket = GtpuReassemblySocket::bind(local, "lo").unwrap();
    assert_eq!(
        socket.send_control_response(retired_plan).unwrap_err(),
        GtpuControlPortError::SocketMismatch
    );
    assert!(peer.recv_from(&mut reply).is_err());
    peer.send_to(&request, destination).unwrap();
    let plan = receive(&socket, 1024).echo_response(budget).unwrap();
    assert_eq!(
        other.send_control_response(plan).unwrap_err(),
        GtpuControlPortError::SocketMismatch
    );
    assert!(peer.recv_from(&mut reply).is_err());
    peer.send_to(&request, destination).unwrap();
    assert_eq!(
        receive(&socket, 1024)
            .echo_response(GtpuControlResponseBudget::new(14, 1).unwrap())
            .unwrap_err(),
        GtpuControlPortError::ResponseBudgetExceeded
    );
    assert!(peer.recv_from(&mut reply).is_err());
    peer.send_to(&request, destination).unwrap();
    assert!(matches!(
        socket.try_receive_datagram(8),
        Err(GtpuControlPortError::Io {
            kind: std::io::ErrorKind::InvalidData
        })
    ));
    assert!(socket.try_receive_datagram(1024).unwrap().is_none());
    // Independent malformed packets never create an Echo reply plan.
    for length in 0..request.len() {
        peer.send_to(&request[..length], destination).unwrap();
        let event = receive(&socket, 1024);
        assert_eq!(event.kind(), GtpuControlDatagramKind::Malformed);
        assert_eq!(
            event.echo_response(budget).unwrap_err(),
            GtpuControlPortError::WrongProcedure
        );
    }
    let mut trailing = request.to_vec();
    trailing.push(0);
    peer.send_to(&trailing, destination).unwrap();
    assert_eq!(
        receive(&socket, 1024).echo_response(budget).unwrap_err(),
        GtpuControlPortError::WrongProcedure
    );
    assert!(peer.recv_from(&mut reply).is_err());
    // The same queue still exposes exact bytes/provenance to reassembly.
    let gpdu = [0x30, 255, 0, 1, 1, 2, 3, 4, 0x45];
    peer.send_to(&gpdu, destination).unwrap();
    let event = receive(&socket, 1024);
    assert_eq!(event.kind(), GtpuControlDatagramKind::Gpdu);
    assert_eq!(event.bytes(), gpdu);
    let source_port = peer.local_addr().unwrap().port();
    socket
        .send_control_response(event.unknown_tunnel_error(budget).unwrap())
        .unwrap();
    let (n, from) = service.recv_from(&mut reply).unwrap();
    assert_eq!(from, std::net::SocketAddr::V4(destination));
    let [hi, lo] = source_port.to_be_bytes();
    assert_eq!(
        &reply[..n],
        &[
            0x36, 26, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0x40, 1, hi, lo, 0, 16, 1, 2, 3, 4, 133, 0, 4,
            127, 0, 0, 2
        ]
    );
    assert!(peer.recv_from(&mut reply).is_err());
    let required = [0x34, 255, 0, 9, 1, 2, 3, 4, 0, 0, 0, 0x80, 1, 0, 0, 0, 0x45];
    peer.send_to(&required, destination).unwrap();
    let event = receive(&socket, 1024);
    assert_eq!(
        event.kind(),
        GtpuControlDatagramKind::UnsupportedRequiredExtension
    );
    let supported = GtpuExtensionHeaderTypeList::new([]).unwrap();
    socket
        .send_control_response(event.extension_notification(supported, budget).unwrap())
        .unwrap();
    let (n, from) = service.recv_from(&mut reply).unwrap();
    assert_eq!(from, std::net::SocketAddr::V4(destination));
    assert_eq!(
        &reply[..n],
        &[0x32, 31, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 141, 0]
    );
    // An existing blocking receive and the new demultiplexer use one queue.
    peer.send_to(&gpdu, destination).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (n, provenance) = socket.receive(&mut reply).unwrap();
    assert_eq!(&reply[..n], gpdu);
    assert_eq!(provenance.peer_address(), remote);
    assert!(socket.try_receive_datagram(1024).unwrap().is_none());
    // Rename the bound interface without changing its ifindex, addresses or
    // socket. Both operations must reject the now-conflicting live binding.
    peer.send_to(&request, destination).unwrap();
    let stale_binding_plan = receive(&socket, 1024).echo_response(budget).unwrap();
    for arguments in [
        ["link", "set", "lo", "down"].as_slice(),
        ["link", "set", "lo", "name", "cplost"].as_slice(),
        ["link", "set", "cplost", "up"].as_slice(),
    ] {
        assert!(std::process::Command::new("ip")
            .args(arguments)
            .status()
            .unwrap()
            .success());
    }
    assert!(matches!(
        socket.send_control_response(stale_binding_plan),
        Err(GtpuControlPortError::Io { .. })
    ));
    assert!(matches!(
        socket.try_receive_datagram(1024),
        Err(GtpuControlPortError::Io { .. })
    ));
    assert!(peer.recv_from(&mut reply).is_err());
    println!("native shared GTP-U control socket: exact tuple, bounded response, required extension, single queue verified");
}
