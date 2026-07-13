use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct NetlinkSocket {
    _private: (),
}

#[derive(Debug)]
pub struct BpffsDirectory {
    _private: (),
}

impl BpffsDirectory {
    pub fn proc_path(&self) -> PathBuf {
        PathBuf::new()
    }
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux XFRM netlink sockets are supported only on Linux",
    )
}

pub fn open_netlink_socket() -> io::Result<NetlinkSocket> {
    Err(unsupported())
}

pub fn send_message(_socket: &NetlinkSocket, _payload: &[u8]) -> io::Result<usize> {
    Err(unsupported())
}

pub fn receive_message(_socket: &NetlinkSocket, _buffer: &mut [u8]) -> io::Result<usize> {
    Err(unsupported())
}

pub fn open_or_create_bpffs_directory(_relative: &Path) -> io::Result<BpffsDirectory> {
    Err(unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_stub_reports_unsupported() {
        let error = match open_netlink_socket() {
            Ok(_) => panic!("unsupported stub unexpectedly opened a socket"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }
}
