use std::io;

#[derive(Debug)]
pub struct NetlinkSocket {
    _private: (),
}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "Linux route netlink is supported only on Linux",
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
