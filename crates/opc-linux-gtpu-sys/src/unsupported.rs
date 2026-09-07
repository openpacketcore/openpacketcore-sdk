use std::io;
use std::path::Path;
use std::time::Duration;

use crate::{BpfXdpLinkInfo, GtpuUdpBind};

#[derive(Debug)]
pub struct BootTimeTimer {
    _private: (),
}

impl BootTimeTimer {
    pub fn new(_duration: Duration) -> io::Result<Self> {
        Err(unsupported())
    }

    pub fn consume_expirations(&self) -> io::Result<u64> {
        Err(unsupported())
    }
}

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

#[derive(Debug)]
pub struct BpfXdpLink {
    _private: (),
}

#[derive(Debug)]
pub struct BpfXdpProgram {
    _private: (),
}

impl BpfXdpProgram {
    pub fn program_id(&self) -> io::Result<u32> {
        Err(unsupported())
    }
}

impl BpfXdpLink {
    pub fn info(&self) -> io::Result<BpfXdpLinkInfo> {
        Err(unsupported())
    }

    pub fn pin_duplicate(&self, _path: &Path) -> io::Result<()> {
        Err(unsupported())
    }

    #[cfg(target_os = "linux")]
    pub fn replace_program(
        &self,
        _new_program_fd: std::os::fd::BorrowedFd<'_>,
        _expected_old_program: &BpfXdpProgram,
    ) -> io::Result<()> {
        Err(unsupported())
    }
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

#[cfg(target_os = "linux")]
pub fn socket_kernel_identity(_socket: std::os::fd::BorrowedFd<'_>) -> io::Result<u64> {
    Err(unsupported())
}

#[cfg(target_os = "linux")]
pub fn verify_udp_fence_socket_options(
    _socket: std::os::fd::BorrowedFd<'_>,
    _ipv6: bool,
) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(target_os = "linux")]
pub fn query_cgroup_skb_egress(
    _cgroup: std::os::fd::BorrowedFd<'_>,
) -> io::Result<(u32, u64, Vec<crate::BpfCgroupProgramAttachment>)> {
    Err(unsupported())
}

#[cfg(target_os = "linux")]
pub fn probe_cgroup_revision_uapi(_cgroup: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(target_os = "linux")]
pub fn attach_cgroup_skb_egress(
    _cgroup: std::os::fd::BorrowedFd<'_>,
    _program: std::os::fd::BorrowedFd<'_>,
    _expected_revision: u64,
) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(target_os = "linux")]
pub fn detach_cgroup_skb_egress(
    _cgroup: std::os::fd::BorrowedFd<'_>,
    _program: std::os::fd::BorrowedFd<'_>,
    _expected_revision: u64,
) -> io::Result<()> {
    Err(unsupported())
}

pub fn clock_gettime_boottime_ns() -> io::Result<u64> {
    Err(unsupported())
}

#[cfg(target_os = "linux")]
pub fn freeze_bpf_map(_map: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    Err(unsupported())
}

#[cfg(target_os = "linux")]
pub fn verify_bpf_map_frozen(_map: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    Err(unsupported())
}

pub fn open_xdp_link_from_pin(_path: &Path) -> io::Result<BpfXdpLink> {
    Err(unsupported())
}

pub fn open_xdp_link_by_id(_link_id: u32) -> io::Result<BpfXdpLink> {
    Err(unsupported())
}

pub fn open_xdp_program_by_id(_program_id: u32) -> io::Result<BpfXdpProgram> {
    Err(unsupported())
}

pub fn send_message(_socket: &NetlinkSocket, _payload: &[u8]) -> io::Result<usize> {
    Err(unsupported())
}

pub fn receive_message(_socket: &NetlinkSocket, _buffer: &mut [u8]) -> io::Result<usize> {
    Err(unsupported())
}

pub fn receive_kernel_message(_socket: &NetlinkSocket, _buffer: &mut [u8]) -> io::Result<usize> {
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

        let timer_error =
            BootTimeTimer::new(Duration::from_secs(1)).expect_err("unsupported boot-time timer");
        assert_eq!(timer_error.kind(), io::ErrorKind::Unsupported);
    }
}
