use std::io;

use crate::GtpuUdpBind;

#[derive(Debug)]
pub struct NetlinkSocket {
    _private: (),
}

impl NetlinkSocket {
    pub fn port_id(&self) -> u32 {
        0
    }
}

#[derive(Debug)]
pub struct GtpuUdpSocket {
    _private: (),
}

impl GtpuUdpSocket {
    pub fn raw_fd(&self) -> i32 {
        -1
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux GTP-U sockets are supported only on Linux",
    )
}

pub fn open_netlink_socket(_protocol: i32) -> io::Result<NetlinkSocket> {
    Err(unsupported())
}

pub fn open_gtpu_udp_socket(_bind: GtpuUdpBind) -> io::Result<GtpuUdpSocket> {
    Err(unsupported())
}

pub fn ifindex_by_name(_name: &str) -> io::Result<u32> {
    Err(unsupported())
}

pub fn send_message(_socket: &NetlinkSocket, _payload: &[u8]) -> io::Result<usize> {
    Err(unsupported())
}

pub fn receive_message(_socket: &NetlinkSocket, _buffer: &mut [u8]) -> io::Result<usize> {
    Err(unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_stub_reports_unsupported() {
        let error = match open_netlink_socket(crate::NETLINK_GENERIC) {
            Ok(_) => panic!("unsupported stub unexpectedly opened a socket"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
