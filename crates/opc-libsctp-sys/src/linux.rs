use std::io;
use std::mem;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr;

use crate::{
    AddressFamily, ConnectStatus, EventSubscriptions, InitMsg, Received, RecvFlags, RecvInfo,
    SendInfo, SocketStyle,
};

pub const SCTP_UNORDERED_FLAG: u16 = libc::SCTP_UNORDERED as u16;
pub const SCTP_NOTIFICATION_FLAG: i32 = libc::SCTP_NOTIFICATION;
pub const SCTP_ASSOC_CHANGE_NOTIFICATION: u16 = 1;
pub const SCTP_SHUTDOWN_EVENT_NOTIFICATION: u16 = 5;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct SctpEventSubscribe {
    data_io_event: u8,
    association_event: u8,
    address_event: u8,
    send_failure_event: u8,
    peer_error_event: u8,
    shutdown_event: u8,
    partial_delivery_event: u8,
    adaptation_layer_event: u8,
    authentication_event: u8,
    sender_dry_event: u8,
}

pub fn open_socket(family: AddressFamily, style: SocketStyle) -> io::Result<OwnedFd> {
    let domain = match family {
        AddressFamily::Ipv4 => libc::AF_INET,
        AddressFamily::Ipv6 => libc::AF_INET6,
    };
    let socket_type = match style {
        SocketStyle::OneToOne => libc::SOCK_STREAM,
        SocketStyle::OneToMany => libc::SOCK_SEQPACKET,
    } | libc::SOCK_NONBLOCK
        | libc::SOCK_CLOEXEC;

    // SAFETY: `socket` is called with constant domain/type/protocol values.
    // On success it returns a new owned fd, which is immediately wrapped in
    // `OwnedFd`; on failure no fd is created and errno is read.
    let fd = unsafe { libc::socket(domain, socket_type, libc::IPPROTO_SCTP) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` is a fresh descriptor returned by `socket` above and is
        // not owned anywhere else.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

pub fn bind(fd: BorrowedFd<'_>, addr: &SocketAddr) -> io::Result<()> {
    let (storage, len) = socket_addr_to_raw(addr);
    // SAFETY: `storage` contains a valid sockaddr for `len`, and `fd` is a
    // borrowed live descriptor owned by the caller.
    cvt(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr>(),
            len,
        )
    })
}

pub fn listen(fd: BorrowedFd<'_>, backlog: i32) -> io::Result<()> {
    // SAFETY: `listen` only observes the borrowed live descriptor and scalar
    // backlog value.
    cvt(unsafe { libc::listen(fd.as_raw_fd(), backlog) })
}

pub fn accept(fd: BorrowedFd<'_>) -> io::Result<(OwnedFd, SocketAddr)> {
    // SAFETY: Zeroed `sockaddr_storage` is a valid receive buffer for `accept4`.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `storage` and `len` are valid writable buffers. The returned fd is
    // owned by this function on success.
    let accepted = unsafe {
        libc::accept4(
            fd.as_raw_fd(),
            (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr>(),
            &mut len,
            libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
        )
    };
    if accepted < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `accepted` is a fresh descriptor returned by `accept4` above.
        let accepted = unsafe { OwnedFd::from_raw_fd(accepted) };
        let addr = raw_to_socket_addr(&storage, len)?;
        Ok((accepted, addr))
    }
}

pub fn connect(fd: BorrowedFd<'_>, addr: &SocketAddr) -> io::Result<ConnectStatus> {
    let (storage, len) = socket_addr_to_raw(addr);
    // SAFETY: `storage` contains a valid sockaddr for `len`, and `fd` is a
    // borrowed live descriptor owned by the caller.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&storage as *const libc::sockaddr_storage).cast::<libc::sockaddr>(),
            len,
        )
    };
    classify_connect_result(rc, Some(io::Error::last_os_error()))
}

fn classify_connect_result(rc: libc::c_int, error: Option<io::Error>) -> io::Result<ConnectStatus> {
    if rc == 0 {
        return Ok(ConnectStatus::Connected);
    }

    let err = error.unwrap_or_else(io::Error::last_os_error);
    if matches!(
        err.raw_os_error(),
        Some(errno) if errno == libc::EINPROGRESS || errno == libc::EINTR || errno == libc::EALREADY
    ) {
        Ok(ConnectStatus::InProgress)
    } else {
        Err(err)
    }
}

pub fn socket_error(fd: BorrowedFd<'_>) -> io::Result<Option<io::Error>> {
    let mut value: libc::c_int = 0;
    let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` are valid writable buffers for SO_ERROR.
    cvt(unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut value as *mut libc::c_int).cast::<libc::c_void>(),
            &mut len,
        )
    })?;
    if value == 0 {
        Ok(None)
    } else {
        Ok(Some(io::Error::from_raw_os_error(value)))
    }
}

pub fn set_initmsg(fd: BorrowedFd<'_>, init: InitMsg) -> io::Result<()> {
    let raw = libc::sctp_initmsg {
        sinit_num_ostreams: init.outbound_streams,
        sinit_max_instreams: init.inbound_streams,
        sinit_max_attempts: init.max_attempts,
        sinit_max_init_timeo: init.max_init_timeout_ms,
    };
    set_sockopt(fd, libc::IPPROTO_SCTP, libc::SCTP_INITMSG, &raw)
}

pub fn set_nodelay(fd: BorrowedFd<'_>, enabled: bool) -> io::Result<()> {
    let raw: libc::c_int = if enabled { 1 } else { 0 };
    set_sockopt(fd, libc::IPPROTO_SCTP, libc::SCTP_NODELAY, &raw)
}

pub fn set_recv_rcvinfo(fd: BorrowedFd<'_>, enabled: bool) -> io::Result<()> {
    let raw: libc::c_int = if enabled { 1 } else { 0 };
    set_sockopt(fd, libc::IPPROTO_SCTP, libc::SCTP_RECVRCVINFO, &raw)
}

pub fn set_events(fd: BorrowedFd<'_>, events: EventSubscriptions) -> io::Result<()> {
    let raw = SctpEventSubscribe {
        data_io_event: events.data_io as u8,
        association_event: events.association as u8,
        address_event: events.address as u8,
        send_failure_event: events.send_failure as u8,
        peer_error_event: events.peer_error as u8,
        shutdown_event: events.shutdown as u8,
        partial_delivery_event: events.partial_delivery as u8,
        adaptation_layer_event: events.adaptation_layer as u8,
        authentication_event: events.authentication as u8,
        sender_dry_event: events.sender_dry as u8,
    };
    set_sockopt(fd, libc::IPPROTO_SCTP, libc::SCTP_EVENTS, &raw)
}

pub fn send_msg(fd: BorrowedFd<'_>, payload: &[u8], info: SendInfo) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: payload.len(),
    };
    let control_len = {
        // SAFETY: The argument is the size of the control-message payload type
        // and the returned buffer size is used only for ancillary data allocation.
        unsafe { libc::CMSG_SPACE(mem::size_of::<libc::sctp_sndinfo>() as libc::c_uint) }
    };
    let mut control = vec![0_u8; control_len as usize];
    // SAFETY: Zeroed `msghdr` is initialized below before `sendmsg`.
    let mut header: libc::msghdr = unsafe { mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    header.msg_controllen = control.len();

    // SAFETY: `header` points at a valid control buffer large enough for one
    // `sctp_sndinfo`, and CMSG helpers return pointers within that buffer.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&header);
        if cmsg.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "control buffer too small for SCTP_SNDINFO",
            ));
        }
        (*cmsg).cmsg_level = libc::IPPROTO_SCTP;
        (*cmsg).cmsg_type = libc::SCTP_SNDINFO;
        (*cmsg).cmsg_len =
            libc::CMSG_LEN(mem::size_of::<libc::sctp_sndinfo>() as libc::c_uint) as _;
        let snd = libc::CMSG_DATA(cmsg).cast::<libc::sctp_sndinfo>();
        ptr::write(
            snd,
            libc::sctp_sndinfo {
                snd_sid: info.stream_id,
                snd_flags: info.flags,
                snd_ppid: info.ppid_network_order,
                snd_context: info.context,
                snd_assoc_id: info.assoc_id,
            },
        );
    }

    // SAFETY: `header` references the immutable payload and initialized control
    // data for the duration of this call; `fd` is borrowed and live.
    let rc = unsafe { libc::sendmsg(fd.as_raw_fd(), &header, libc::MSG_NOSIGNAL) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

pub fn recv_msg(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<Received> {
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: buffer.len(),
    };
    let control_len = {
        // SAFETY: The arguments are the sizes of the control-message payload
        // types and the returned buffer size is used only for ancillary data
        // allocation. Space for both the modern `sctp_rcvinfo` and the legacy
        // `sctp_sndrcvinfo` keeps `recvmsg` from setting MSG_CTRUNC when a
        // kernel or subscription delivers more than one receive-info cmsg.
        unsafe {
            libc::CMSG_SPACE(mem::size_of::<libc::sctp_rcvinfo>() as libc::c_uint)
                + libc::CMSG_SPACE(mem::size_of::<libc::sctp_sndrcvinfo>() as libc::c_uint)
        }
    };
    let mut control = vec![0_u8; control_len as usize];
    // SAFETY: Zeroed `msghdr` is initialized below before `recvmsg`.
    let mut header: libc::msghdr = unsafe { mem::zeroed() };
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    header.msg_control = control.as_mut_ptr().cast::<libc::c_void>();
    header.msg_controllen = control.len();

    // SAFETY: `header` references valid payload/control buffers for `recvmsg`;
    // `fd` is borrowed and live.
    let rc = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut header, 0) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut info = None;
    // SAFETY: `header` contains the control buffer just filled by `recvmsg`.
    // `CMSG_FIRSTHDR`/`CMSG_NXTHDR` only yield headers within that buffer, so
    // the walk stays in bounds; the level/type/length checks prove the cmsg
    // payload holds an `sctp_rcvinfo` before it is read. The kernel may
    // deliver other cmsgs (e.g. the legacy `sctp_sndrcvinfo`) first, so the
    // walk must not assume `SCTP_RCVINFO` is the first header.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&header);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::IPPROTO_SCTP
                && (*cmsg).cmsg_type == libc::SCTP_RCVINFO
                && (*cmsg).cmsg_len
                    >= libc::CMSG_LEN(mem::size_of::<libc::sctp_rcvinfo>() as libc::c_uint) as _
            {
                let raw = ptr::read(libc::CMSG_DATA(cmsg).cast::<libc::sctp_rcvinfo>());
                info = Some(RecvInfo {
                    stream_id: raw.rcv_sid,
                    ssn: raw.rcv_ssn,
                    flags: raw.rcv_flags,
                    ppid_network_order: raw.rcv_ppid,
                    tsn: raw.rcv_tsn,
                    cumulative_tsn: raw.rcv_cumtsn,
                    context: raw.rcv_context,
                    assoc_id: raw.rcv_assoc_id,
                });
                break;
            }
            cmsg = libc::CMSG_NXTHDR(&header, cmsg);
        }
    }

    Ok(Received {
        bytes: rc as usize,
        info,
        flags: RecvFlags {
            notification: (header.msg_flags & libc::MSG_NOTIFICATION) != 0,
            end_of_record: (header.msg_flags & libc::MSG_EOR) != 0,
            payload_truncated: (header.msg_flags & libc::MSG_TRUNC) != 0,
            control_truncated: (header.msg_flags & libc::MSG_CTRUNC) != 0,
        },
    })
}

fn set_sockopt<T>(
    fd: BorrowedFd<'_>,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> io::Result<()> {
    // SAFETY: `value` points to a properly initialized option payload of the
    // length passed to `setsockopt`; `fd` is borrowed and live.
    cvt(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (value as *const T).cast::<libc::c_void>(),
            mem::size_of::<T>() as libc::socklen_t,
        )
    })
}

fn cvt(rc: libc::c_int) -> io::Result<()> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn socket_addr_to_raw(addr: &SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: Zeroed `sockaddr_storage` is a valid backing buffer; a concrete
    // sockaddr matching `addr` is written into the prefix below.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    match addr {
        SocketAddr::V4(addr) => {
            let raw = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: `storage` is large enough and aligned for `sockaddr_in`.
            unsafe {
                ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>(),
                    raw,
                );
            }
            (
                storage,
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SocketAddr::V6(addr) => {
            let raw = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            // SAFETY: `storage` is large enough and aligned for `sockaddr_in6`.
            unsafe {
                ptr::write(
                    (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>(),
                    raw,
                );
            }
            (
                storage,
                mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
    }
}

fn raw_to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET if len as usize >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: The family/length check above proves the prefix contains
            // a `sockaddr_in` written by the kernel.
            let raw = unsafe {
                ptr::read((storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>())
            };
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(raw.sin_port),
            )))
        }
        libc::AF_INET6 if len as usize >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: The family/length check above proves the prefix contains
            // a `sockaddr_in6` written by the kernel.
            let raw = unsafe {
                ptr::read((storage as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>())
            };
            Ok(SocketAddr::V6(SocketAddrV6::new(
                raw.sin6_addr.s6_addr.into(),
                u16::from_be(raw.sin6_port),
                raw.sin6_flowinfo,
                raw.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported socket address family",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};
    use std::os::fd::AsFd;

    const TEST_INIT: InitMsg = InitMsg {
        outbound_streams: 8,
        inbound_streams: 8,
        max_attempts: 4,
        max_init_timeout_ms: 1000,
    };

    fn wait_fd(fd: BorrowedFd<'_>, events: libc::c_short) {
        let mut poll_fd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: `poll_fd` is a valid single-entry pollfd array for `poll`.
        let rc = unsafe { libc::poll(&mut poll_fd, 1, 5000) };
        assert!(rc > 0, "poll timed out waiting for fd readiness");
    }

    fn local_addr(fd: BorrowedFd<'_>) -> SocketAddr {
        // SAFETY: Zeroed `sockaddr_storage` is a valid receive buffer.
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        // SAFETY: `storage` and `len` are valid writable buffers for `getsockname`.
        let rc = unsafe {
            libc::getsockname(
                fd.as_raw_fd(),
                (&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr>(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockname failed");
        raw_to_socket_addr(&storage, len).unwrap()
    }

    fn recv_data_message(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> Received {
        for _ in 0..100 {
            wait_fd(fd, libc::POLLIN);
            match recv_msg(fd, buffer) {
                Ok(received) if received.flags.notification => continue,
                Ok(received) => return received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => panic!("recv_msg failed: {error}"),
            }
        }
        panic!("no SCTP DATA message received");
    }

    #[test]
    fn libc_sctp_layouts_match_expected_linux_uapi_shape() {
        assert_eq!(size_of::<libc::sctp_initmsg>(), 8);
        assert_eq!(align_of::<libc::sctp_initmsg>(), 2);
        assert_eq!(offset_of!(libc::sctp_sndinfo, snd_sid), 0);
        assert_eq!(offset_of!(libc::sctp_sndinfo, snd_flags), 2);
        assert_eq!(offset_of!(libc::sctp_sndinfo, snd_ppid), 4);
        assert_eq!(offset_of!(libc::sctp_sndinfo, snd_context), 8);
        assert_eq!(offset_of!(libc::sctp_sndinfo, snd_assoc_id), 12);
        assert_eq!(size_of::<libc::sctp_sndinfo>(), 16);
        assert_eq!(offset_of!(libc::sctp_rcvinfo, rcv_sid), 0);
        assert_eq!(offset_of!(libc::sctp_rcvinfo, rcv_ppid), 8);
        assert_eq!(offset_of!(libc::sctp_rcvinfo, rcv_assoc_id), 24);
        assert_eq!(size_of::<libc::sctp_rcvinfo>(), 28);
        assert_eq!(size_of::<SctpEventSubscribe>(), 10);
        assert_eq!(align_of::<SctpEventSubscribe>(), 1);
    }

    #[test]
    fn socket_addr_round_trips_v4_and_v6() {
        let v4: SocketAddr = "127.0.0.1:38412".parse().unwrap();
        let (raw, len) = socket_addr_to_raw(&v4);
        assert_eq!(raw_to_socket_addr(&raw, len).unwrap(), v4);

        let v6: SocketAddr = "[::1]:38412".parse().unwrap();
        let (raw, len) = socket_addr_to_raw(&v6);
        assert_eq!(raw_to_socket_addr(&raw, len).unwrap(), v6);
    }

    #[test]
    fn socket_open_failure_is_reported_without_panic() {
        match open_socket(AddressFamily::Ipv4, SocketStyle::OneToOne) {
            Ok(fd) => drop(fd),
            Err(error) => {
                let code = error.raw_os_error().unwrap_or_default();
                assert!(code == libc::EPROTONOSUPPORT || code == libc::EAFNOSUPPORT);
            }
        }
    }

    #[test]
    fn connect_errno_classification_keeps_async_connect_in_progress() {
        assert_eq!(
            classify_connect_result(0, None).unwrap(),
            ConnectStatus::Connected
        );

        for errno in [libc::EINPROGRESS, libc::EINTR, libc::EALREADY] {
            assert_eq!(
                classify_connect_result(-1, Some(io::Error::from_raw_os_error(errno))).unwrap(),
                ConnectStatus::InProgress,
                "errno={errno}"
            );
        }

        let refused =
            classify_connect_result(-1, Some(io::Error::from_raw_os_error(libc::ECONNREFUSED)))
                .unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::ECONNREFUSED));
    }

    #[test]
    #[ignore = "requires Linux kernel SCTP support"]
    fn loopback_data_receive_keeps_control_data_intact() {
        let listener = open_socket(AddressFamily::Ipv4, SocketStyle::OneToOne).unwrap();
        set_initmsg(listener.as_fd(), TEST_INIT).unwrap();
        set_recv_rcvinfo(listener.as_fd(), true).unwrap();
        set_events(listener.as_fd(), EventSubscriptions::default()).unwrap();
        bind(listener.as_fd(), &"127.0.0.1:0".parse().unwrap()).unwrap();
        listen(listener.as_fd(), 8).unwrap();
        let server_addr = local_addr(listener.as_fd());

        let client = open_socket(AddressFamily::Ipv4, SocketStyle::OneToOne).unwrap();
        set_initmsg(client.as_fd(), TEST_INIT).unwrap();
        if connect(client.as_fd(), &server_addr).unwrap() == ConnectStatus::InProgress {
            wait_fd(client.as_fd(), libc::POLLOUT);
            assert!(socket_error(client.as_fd()).unwrap().is_none());
        }

        wait_fd(listener.as_fd(), libc::POLLIN);
        let (accepted, _peer) = accept(listener.as_fd()).unwrap();

        let payload = vec![0xAB_u8; 300];
        let ppid_network_order = 46_u32.to_be();
        let sent = send_msg(
            client.as_fd(),
            &payload,
            SendInfo {
                stream_id: 1,
                flags: 0,
                ppid_network_order,
                context: 0,
                assoc_id: 0,
            },
        )
        .unwrap();
        assert_eq!(sent, payload.len());

        let mut buffer = vec![0_u8; 64 * 1024];
        let received = recv_data_message(accepted.as_fd(), &mut buffer);
        assert_eq!(received.bytes, payload.len());
        assert!(received.flags.end_of_record);
        assert!(!received.flags.payload_truncated);
        assert!(
            !received.flags.control_truncated,
            "kernel truncated SCTP ancillary data (MSG_CTRUNC)"
        );
        let info = received.info.expect("SCTP_RCVINFO control message missing");
        assert_eq!(info.stream_id, 1);
        assert_eq!(info.ppid_network_order, ppid_network_order);
    }

    #[test]
    #[ignore = "requires Linux kernel SCTP support"]
    fn loopback_sctp_socket_can_open() {
        let fd = open_socket(AddressFamily::Ipv4, SocketStyle::OneToOne).unwrap();
        set_initmsg(
            fd.as_fd(),
            InitMsg {
                outbound_streams: 8,
                inbound_streams: 8,
                max_attempts: 4,
                max_init_timeout_ms: 1000,
            },
        )
        .unwrap();
        set_recv_rcvinfo(fd.as_fd(), true).unwrap();
        set_events(fd.as_fd(), EventSubscriptions::default()).unwrap();
    }
}
