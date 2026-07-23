use std::io;
use std::net::SocketAddr;
use std::os::fd::{BorrowedFd, OwnedFd};

use crate::{
    AddressFamily, ConnectStatus, EventSubscriptions, InitMsg, PeerAddressParameters, Received,
    RtoParameters, SendInfo, SocketStyle,
};

pub const SCTP_UNORDERED_FLAG: u16 = 1;
pub const SCTP_NOTIFICATION_FLAG: i32 = 0x8000;
const SCTP_NOTIFICATION_TYPE_BASE: u16 = 1 << 15;
pub const SCTP_ASSOC_CHANGE_NOTIFICATION: u16 = SCTP_NOTIFICATION_TYPE_BASE + 1;
pub const SCTP_PEER_ADDR_CHANGE_NOTIFICATION: u16 = SCTP_NOTIFICATION_TYPE_BASE + 2;
pub const SCTP_SHUTDOWN_EVENT_NOTIFICATION: u16 = SCTP_NOTIFICATION_TYPE_BASE + 5;
pub const SCTP_AUTHENTICATION_EVENT_NOTIFICATION: u16 = SCTP_NOTIFICATION_TYPE_BASE + 8;
pub const SCTP_SENDER_DRY_EVENT_NOTIFICATION: u16 = SCTP_NOTIFICATION_TYPE_BASE + 9;

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

pub fn bind_addresses(_fd: BorrowedFd<'_>, _addrs: &[SocketAddr]) -> io::Result<()> {
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

pub fn connect_addresses(_fd: BorrowedFd<'_>, _addrs: &[SocketAddr]) -> io::Result<ConnectStatus> {
    Err(unsupported())
}

pub fn local_addresses(_fd: BorrowedFd<'_>, _assoc_id: i32) -> io::Result<Vec<SocketAddr>> {
    Err(unsupported())
}

pub fn peer_addresses(_fd: BorrowedFd<'_>, _assoc_id: i32) -> io::Result<Vec<SocketAddr>> {
    Err(unsupported())
}

pub fn peer_primary_address(_fd: BorrowedFd<'_>) -> io::Result<SocketAddr> {
    Err(unsupported())
}

pub fn is_multihoming_unavailable(_error: &io::Error) -> bool {
    true
}

pub fn is_sctp_capability_unavailable(_error: &io::Error) -> bool {
    true
}

pub fn socket_error(_fd: BorrowedFd<'_>) -> io::Result<Option<io::Error>> {
    Err(unsupported())
}

pub fn set_initmsg(_fd: BorrowedFd<'_>, _init: InitMsg) -> io::Result<()> {
    Err(unsupported())
}

pub fn set_rto_parameters(_fd: BorrowedFd<'_>, _parameters: RtoParameters) -> io::Result<()> {
    Err(unsupported())
}

pub fn set_peer_address_parameters(
    _fd: BorrowedFd<'_>,
    _parameters: PeerAddressParameters,
) -> io::Result<()> {
    Err(unsupported())
}

pub fn set_primary_peer_address(
    _fd: BorrowedFd<'_>,
    _assoc_id: i32,
    _peer_addr: &SocketAddr,
) -> io::Result<()> {
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

pub fn require_authenticated_chunk(_fd: BorrowedFd<'_>, _chunk_type: u8) -> io::Result<()> {
    Err(unsupported())
}

pub fn set_authentication_enabled(_fd: BorrowedFd<'_>, _enabled: bool) -> io::Result<()> {
    Err(unsupported())
}

pub fn peer_authentication_supported(_fd: BorrowedFd<'_>, _assoc_id: i32) -> io::Result<bool> {
    Err(unsupported())
}

pub fn peer_authenticated_chunks(_fd: BorrowedFd<'_>, _assoc_id: i32) -> io::Result<Vec<u8>> {
    Err(unsupported())
}

pub fn set_event(
    _fd: BorrowedFd<'_>,
    _assoc_id: i32,
    _event_type: u16,
    _enabled: bool,
) -> io::Result<()> {
    Err(unsupported())
}

pub fn install_auth_key(
    _fd: BorrowedFd<'_>,
    _assoc_id: i32,
    _key_id: u16,
    _key: &[u8],
) -> io::Result<()> {
    Err(unsupported())
}

pub fn set_active_auth_key(_fd: BorrowedFd<'_>, _assoc_id: i32, _key_id: u16) -> io::Result<()> {
    Err(unsupported())
}

pub fn deactivate_auth_key(_fd: BorrowedFd<'_>, _assoc_id: i32, _key_id: u16) -> io::Result<()> {
    Err(unsupported())
}

pub fn delete_auth_key(_fd: BorrowedFd<'_>, _assoc_id: i32, _key_id: u16) -> io::Result<()> {
    Err(unsupported())
}

pub fn shutdown_both(_fd: BorrowedFd<'_>) -> io::Result<()> {
    Err(unsupported())
}

pub fn send_msg(_fd: BorrowedFd<'_>, _payload: &[u8], _info: SendInfo) -> io::Result<usize> {
    Err(unsupported())
}

pub fn recv_msg(_fd: BorrowedFd<'_>, _buffer: &mut [u8]) -> io::Result<Received> {
    Err(unsupported())
}
