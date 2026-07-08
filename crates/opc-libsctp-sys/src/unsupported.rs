use std::io;
use std::net::SocketAddr;
use std::os::fd::{BorrowedFd, OwnedFd};

use crate::{
    AddressFamily, ConnectStatus, EventSubscriptions, InitMsg, Received, SendInfo, SocketStyle,
};

pub const SCTP_UNORDERED_FLAG: u16 = 1;
pub const SCTP_NOTIFICATION_FLAG: i32 = 0x8000;
pub const SCTP_ASSOC_CHANGE_NOTIFICATION: u16 = 1;
pub const SCTP_SHUTDOWN_EVENT_NOTIFICATION: u16 = 5;

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "SCTP sockets are supported only on Linux",
    )
}

pub fn open_socket(_family: AddressFamily, _style: SocketStyle) -> io::Result<OwnedFd> {
    Err(unsupported())
}

pub fn bind(_fd: BorrowedFd<'_>, _addr: &SocketAddr) -> io::Result<()> {
    Err(unsupported())
}

pub fn listen(_fd: BorrowedFd<'_>, _backlog: i32) -> io::Result<()> {
    Err(unsupported())
}

pub fn accept(_fd: BorrowedFd<'_>) -> io::Result<(OwnedFd, SocketAddr)> {
    Err(unsupported())
}

pub fn connect(_fd: BorrowedFd<'_>, _addr: &SocketAddr) -> io::Result<ConnectStatus> {
    Err(unsupported())
}

pub fn socket_error(_fd: BorrowedFd<'_>) -> io::Result<Option<io::Error>> {
    Err(unsupported())
}

pub fn set_initmsg(_fd: BorrowedFd<'_>, _init: InitMsg) -> io::Result<()> {
    Err(unsupported())
}

pub fn set_nodelay(_fd: BorrowedFd<'_>, _enabled: bool) -> io::Result<()> {
    Err(unsupported())
}

pub fn set_recv_rcvinfo(_fd: BorrowedFd<'_>, _enabled: bool) -> io::Result<()> {
    Err(unsupported())
}

pub fn set_events(_fd: BorrowedFd<'_>, _events: EventSubscriptions) -> io::Result<()> {
    Err(unsupported())
}

pub fn send_msg(_fd: BorrowedFd<'_>, _payload: &[u8], _info: SendInfo) -> io::Result<usize> {
    Err(unsupported())
}

pub fn recv_msg(_fd: BorrowedFd<'_>, _buffer: &mut [u8]) -> io::Result<Received> {
    Err(unsupported())
}
