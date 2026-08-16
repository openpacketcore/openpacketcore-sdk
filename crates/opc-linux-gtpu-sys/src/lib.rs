//! Narrow Linux GTP-U, socket-identity, suspend-aware time, and BPF UAPI
//! boundary.
//!
//! This crate owns raw Linux socket syscalls and selected UAPI constants needed
//! by safe protocol-neutral dataplane backends. Its BPF surface includes exact
//! XDP-link inspection/handoff and direct root-cgroup `cgroup_skb/egress`
//! query, revision-aware closed-first attach, and exact revision-guarded
//! detach. It also exposes full-width socket cookies, strict fenced-UDP option
//! readback, map freeze/readback, and fallible `CLOCK_BOOTTIME` primitives. It
//! deliberately does not implement packet encoding, subscriber lifecycle
//! policy, route steering, XFRM policy, lease authority, or product deployment
//! defaults.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

use std::io;
use std::path::Path;

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
mod linux;
#[cfg_attr(
    all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)),
    allow(dead_code)
)]
mod unsupported;

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
use linux as platform;
#[cfg(any(not(target_os = "linux"), opc_linux_gtpu_sys_force_unsupported))]
use unsupported as platform;

/// Linux netlink protocol number for route netlink.
pub const NETLINK_ROUTE: i32 = 0;
/// Linux netlink protocol number for generic netlink.
pub const NETLINK_GENERIC: i32 = 16;

/// One nonblocking, close-on-exec relative `CLOCK_BOOTTIME` timer.
///
/// Linux `CLOCK_BOOTTIME` advances across system suspend, so readiness is not
/// deferred until a full monotonic interval elapses after resume. The timer is
/// one-shot and owns its descriptor. Formatting never emits the descriptor or
/// armed duration.
pub struct BootTimeTimer {
    inner: platform::BootTimeTimer,
}

impl BootTimeTimer {
    /// Create and arm a one-shot relative boot-time timer.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when `duration` is zero or cannot be
    /// represented by the kernel time ABI, timer creation or arming fails, or
    /// this platform does not support Linux boot-time timerfds.
    pub fn new(duration: std::time::Duration) -> io::Result<Self> {
        platform::BootTimeTimer::new(duration)
            .map(|inner| Self { inner })
            .map_err(redact_boot_time_timer_error)
    }

    /// Consume one readable timerfd expiration counter.
    ///
    /// This nonblocking operation returns [`io::ErrorKind::WouldBlock`] until
    /// the timer expires. Tokio callers can use it inside
    /// `AsyncFdReadyGuard::try_io` after waiting for readable readiness.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when the timer is not ready or the kernel
    /// does not return one complete nonzero expiration counter.
    pub fn consume_expirations(&self) -> io::Result<u64> {
        self.inner
            .consume_expirations()
            .map_err(redact_boot_time_timer_error)
    }
}

impl std::fmt::Debug for BootTimeTimer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BootTimeTimer(<redacted>)")
    }
}

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
impl std::os::fd::AsFd for BootTimeTimer {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
impl std::os::fd::AsRawFd for BootTimeTimer {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.inner.as_raw_fd()
    }
}

fn redact_boot_time_timer_error(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), "boot_time_timer")
}

/// Netlink close-on-exec/nonblocking socket.
#[derive(Debug)]
pub struct NetlinkSocket {
    inner: platform::NetlinkSocket,
}

impl NetlinkSocket {
    /// Return the kernel-assigned local netlink port identifier.
    #[must_use]
    pub fn port_id(&self) -> u32 {
        self.inner.port_id()
    }

    /// Borrow the underlying Linux file descriptor.
    #[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// Bound UDP socket passed to the kernel GTP-U netdevice.
#[derive(Debug)]
pub struct GtpuUdpSocket {
    inner: platform::GtpuUdpSocket,
}

impl GtpuUdpSocket {
    /// Return the raw file descriptor number needed by `IFLA_GTP_FD1`.
    #[must_use]
    pub fn raw_fd(&self) -> i32 {
        self.inner.raw_fd()
    }

    /// Borrow the underlying Linux file descriptor.
    ///
    /// The kernel GTP netdevice takes its own reference to this socket from the
    /// fd *number* passed as `IFLA_GTP_FD1`; the owning handle stays here. This
    /// crate never sets `IFLA_GTP_CREATE_SOCKETS`, so the netdevice does not
    /// create a socket of its own and `gtp1u_udp_encap_recv` passes messages
    /// back up to this socket's ordinary receive queue.
    ///
    /// That queue is not a control-only channel. `drivers/net/gtp.c` passes a
    /// datagram up when it is not a G-PDU, *and* when it is a G-PDU whose TEID
    /// matches no PDP context — the "No PDP ctx to decap" path, which is
    /// precisely the TS 29.281 7.3.1 Error Indication trigger. Datagrams
    /// shorter than the eight-octet GTPv1 header are dropped in-kernel and
    /// never arrive. A reader must therefore dispatch on the message type
    /// rather than assume everything here is control traffic.
    ///
    /// A borrow rather than the raw number, so a caller reading that queue does
    /// not have to reconstruct ownership it was never given, and so crates that
    /// `forbid(unsafe_code)` can use it. Ownership does not transfer.
    #[cfg(all(target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
    #[must_use]
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// IP address accepted by the raw GTP-U UDP socket binder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpuIpAddress {
    /// IPv4 address as four octets.
    Ipv4([u8; 4]),
    /// IPv6 address as sixteen octets.
    Ipv6([u8; 16]),
}

/// Kernel identity of one XDP BPF-link attachment.
///
/// This contains only kernel object identifiers and an interface index; it
/// carries no packet, subscriber, or key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfXdpLinkInfo {
    /// Kernel BPF-link identifier.
    pub link_id: u32,
    /// Kernel BPF-program identifier currently attached through the link.
    pub program_id: u32,
    /// Target interface index in the current network namespace.
    pub ifindex: u32,
}

/// One exact program attachment returned by a cgroup-BPF query.
///
/// The legacy cgroup query ABI does not report whether a program was attached
/// directly or through a BPF link. Callers must establish direct-attachment
/// provenance through the installer that invokes [`attach_cgroup_skb_egress`],
/// then correlate this program identifier with its staged pinned objects.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BpfCgroupProgramAttachment {
    program_id: u32,
    program_attach_flags: u32,
}

impl BpfCgroupProgramAttachment {
    /// Kernel program identifier.
    #[must_use]
    pub const fn program_id(self) -> u32 {
        self.program_id
    }

    /// Per-program attachment flags returned by the kernel.
    #[must_use]
    pub const fn program_attach_flags(self) -> u32 {
        self.program_attach_flags
    }
}

impl std::fmt::Debug for BpfCgroupProgramAttachment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BpfCgroupProgramAttachment")
            .field(
                "program_attach_flags_present",
                &(self.program_attach_flags != 0),
            )
            .finish()
    }
}

/// Bounded exact-program inventory for one cgroup attach point.
///
/// Program identifiers are kernel object metadata, not packet or subscriber
/// data. The custom [`std::fmt::Debug`] implementation nevertheless reports
/// only the count so diagnostics cannot become an accidental topology
/// inventory.
#[derive(Clone, PartialEq, Eq)]
pub struct BpfCgroupProgramQuery {
    attach_flags: u32,
    revision: u64,
    attachments: Vec<BpfCgroupProgramAttachment>,
}

impl BpfCgroupProgramQuery {
    /// Attachment flags shared by the queried cgroup program list.
    #[must_use]
    pub const fn attach_flags(&self) -> u32 {
        self.attach_flags
    }

    /// Kernel attachment-set revision returned with this exact query.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Exact ordered kernel attachments at the queried attach point.
    #[must_use]
    pub fn attachments(&self) -> &[BpfCgroupProgramAttachment] {
        &self.attachments
    }
}

impl std::fmt::Debug for BpfCgroupProgramQuery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BpfCgroupProgramQuery")
            .field("attach_flags_present", &(self.attach_flags != 0))
            .field("revision_verified", &true)
            .field("program_count", &self.attachments.len())
            .finish()
    }
}

/// Redacted full-width kernel cookie for one exact Linux socket.
///
/// This value binds BPF map state to the exact socket. Formatting never emits
/// the value.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SocketKernelIdentity {
    socket_cookie: u64,
}

#[cfg(target_os = "linux")]
impl SocketKernelIdentity {
    /// Nonzero `SO_COOKIE` read from the exact descriptor.
    #[must_use]
    pub const fn socket_cookie(self) -> u64 {
        self.socket_cookie
    }
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for SocketKernelIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SocketKernelIdentity(<redacted>)")
    }
}

/// Owned close-on-exec descriptor for one exact XDP BPF-link object.
///
/// Keeping this value alive keeps the unpinned link attached. Dropping the
/// last descriptor detaches an unpinned link.
#[derive(Debug)]
pub struct BpfXdpLink {
    inner: platform::BpfXdpLink,
}

/// Owned close-on-exec descriptor for one exact XDP program.
#[derive(Debug)]
pub struct BpfXdpProgram {
    inner: platform::BpfXdpProgram,
}

impl BpfXdpProgram {
    /// Read the kernel program identifier from this exact descriptor.
    pub fn program_id(&self) -> io::Result<u32> {
        self.inner.program_id()
    }
}

impl BpfXdpLink {
    /// Read the current identity from this exact link descriptor.
    pub fn info(&self) -> io::Result<BpfXdpLinkInfo> {
        self.inner.info()
    }

    /// Pin another reference to this exact link descriptor at `path`.
    ///
    /// A failure leaves this owned descriptor and its attachment unchanged.
    pub fn pin_duplicate(&self, path: &Path) -> io::Result<()> {
        self.inner.pin_duplicate(path)
    }

    /// Atomically replace the program on this exact link only if the current
    /// program still matches `expected_old_program`.
    #[cfg(target_os = "linux")]
    pub fn replace_program(
        &self,
        new_program_fd: std::os::fd::BorrowedFd<'_>,
        expected_old_program: &BpfXdpProgram,
    ) -> io::Result<()> {
        self.inner
            .replace_program(new_program_fd, &expected_old_program.inner)
    }
}

/// UDP bind request for a GTP-U socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GtpuUdpBind {
    /// Local address to bind.
    pub address: GtpuIpAddress,
    /// Local UDP port in host byte order.
    pub port: u16,
}

/// Open a nonblocking close-on-exec `NETLINK_ROUTE` socket bound to the process.
pub fn open_route_netlink_socket() -> io::Result<NetlinkSocket> {
    platform::open_netlink_socket(NETLINK_ROUTE).map(|inner| NetlinkSocket { inner })
}

/// Open a nonblocking close-on-exec `NETLINK_GENERIC` socket bound to the process.
pub fn open_generic_netlink_socket() -> io::Result<NetlinkSocket> {
    platform::open_netlink_socket(NETLINK_GENERIC).map(|inner| NetlinkSocket { inner })
}

/// Open and bind a UDP socket for GTP-U user-plane traffic.
pub fn open_gtpu_udp_socket(bind: GtpuUdpBind) -> io::Result<GtpuUdpSocket> {
    platform::open_gtpu_udp_socket(bind).map(|inner| GtpuUdpSocket { inner })
}

/// Return the interface index for `name` in the current network namespace.
pub fn ifindex_by_name(name: &str) -> io::Result<u32> {
    platform::ifindex_by_name(name)
}

/// Read the exact nonzero full-width `SO_COOKIE`.
///
/// # Errors
///
/// Returns a value-free operating-system error when the read fails, has an
/// unexpected width, or returns zero.
#[cfg(target_os = "linux")]
pub fn socket_kernel_identity(
    socket: std::os::fd::BorrowedFd<'_>,
) -> io::Result<SocketKernelIdentity> {
    let socket_cookie = platform::socket_kernel_identity(socket)?;
    if socket_cookie == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "socket_kernel_identity_zero",
        ));
    }
    Ok(SocketKernelIdentity { socket_cookie })
}

/// Prove socket options required for exclusive fenced UDP ownership.
///
/// `ipv6` must match the exact local endpoint family. IPv4 admission requires
/// both `IP_FREEBIND` and `IP_TRANSPARENT` to be disabled. IPv6 admission
/// additionally requires `IPV6_V6ONLY`, preventing an alternate IPv4-mapped
/// send path from bypassing an IPv6 protected endpoint.
///
/// # Errors
///
/// Returns a value-free error when any option cannot be read exactly or an
/// unsafe option is enabled.
#[cfg(target_os = "linux")]
pub fn verify_udp_fence_socket_options(
    socket: std::os::fd::BorrowedFd<'_>,
    ipv6: bool,
) -> io::Result<()> {
    platform::verify_udp_fence_socket_options(socket, ipv6)
        .map_err(|error| io::Error::new(error.kind(), "udp_fence_socket_options"))
}

/// Query the locally attached cgroup-v2 INET-egress programs.
///
/// The inventory is hard-bounded to the kernel cgroup-BPF limit of 64
/// programs. A larger or internally inconsistent result fails closed instead
/// of returning a truncated list. Revision zero is the valid initial value for
/// an attachment point that has never been mutated. The implementation uses a
/// nonzero input sentinel and requires the cgroup revision UAPI to overwrite
/// it, so a pre-v6.17 cgroup query implementation that ignores this field
/// cannot be mistaken for a pristine attachment point.
///
/// # Errors
///
/// Returns a value-free operating-system error when the descriptor is not a
/// cgroup-v2 directory, the caller lacks BPF authority, the query is
/// unsupported, or the kernel reports an invalid or over-capacity inventory.
#[cfg(target_os = "linux")]
pub fn query_cgroup_skb_egress(
    cgroup: std::os::fd::BorrowedFd<'_>,
) -> io::Result<BpfCgroupProgramQuery> {
    let (attach_flags, revision, attachments) = platform::query_cgroup_skb_egress(cgroup)?;
    Ok(BpfCgroupProgramQuery {
        attach_flags,
        revision,
        attachments,
    })
}

/// Prove that cgroup program-list revisions are implemented by this kernel.
///
/// This is a side-effect-free count-only `BPF_PROG_QUERY`. It is intentionally
/// independent of the returned revision value: zero is valid for a pristine
/// attachment point. Callers may use it as an explicit admission probe, while
/// [`query_cgroup_skb_egress`] and the mutation wrappers also enforce the same
/// probe internally.
///
/// # Errors
///
/// Returns a value-free operating-system error when the query is denied,
/// malformed, or the kernel leaves the revision sentinel unchanged.
#[cfg(target_os = "linux")]
pub fn probe_cgroup_revision_uapi(cgroup: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    platform::probe_cgroup_revision_uapi(cgroup)
}

/// Directly attach one cgroup-skb program to cgroup-v2 INET egress.
///
/// This deliberately uses `BPF_PROG_ATTACH` with `BPF_F_ALLOW_MULTI`, not a
/// BPF link. The cgroup therefore owns a program reference independently of
/// process descriptors and bpffs pins. `expected_revision` must come from the
/// exact immediately preceding root query. A nonzero revision provides a
/// kernel compare-and-swap guard; zero is the valid pristine value but cannot
/// enable that kernel guard, so callers must attach a closed gate first and
/// require an exact revision-one, single-program readback. The runtime revision
/// probe is enforced before mutation.
///
/// # Errors
///
/// Returns a value-free operating-system error on an invalid descriptor,
/// incompatible existing attach mode, missing BPF authority, or kernel
/// rejection.
#[cfg(target_os = "linux")]
pub fn attach_cgroup_skb_egress(
    cgroup: std::os::fd::BorrowedFd<'_>,
    program: std::os::fd::BorrowedFd<'_>,
    expected_revision: u64,
) -> io::Result<()> {
    platform::attach_cgroup_skb_egress(cgroup, program, expected_revision)
}

/// Detach one exact directly attached cgroup-skb INET-egress program.
///
/// This wrapper never requests a broad detach: `program` is always passed as
/// the exact target program and `expected_revision` must be nonzero. A
/// concurrent attachment-list mutation is rejected by the kernel with
/// `ESTALE`. The runtime revision probe is enforced before mutation.
///
/// # Errors
///
/// Returns a value-free operating-system error for a zero revision, invalid
/// descriptors, unsupported revision UAPI, missing authority, a non-attached
/// exact program, or a concurrent revision change.
#[cfg(target_os = "linux")]
pub fn detach_cgroup_skb_egress(
    cgroup: std::os::fd::BorrowedFd<'_>,
    program: std::os::fd::BorrowedFd<'_>,
    expected_revision: u64,
) -> io::Result<()> {
    platform::detach_cgroup_skb_egress(cgroup, program, expected_revision)
}

/// Read suspend-aware Linux `CLOCK_BOOTTIME` in nanoseconds.
///
/// Unlike fixed-clock convenience APIs, this preserves the fallible
/// `clock_gettime(2)` boundary and rejects negative, non-canonical, or
/// overflowing `timespec` values.
///
/// # Errors
///
/// Returns a value-free operating-system error when the clock read or checked
/// nanosecond conversion fails.
pub fn clock_gettime_boottime_ns() -> io::Result<u64> {
    platform::clock_gettime_boottime_ns()
}

/// Freeze a BPF map against every subsequent syscall-side mutation.
///
/// BPF programs that already reference the map retain their verifier-approved
/// mutation rights. This distinction lets an unattached control program own
/// authorization transitions while preventing direct userspace writes.
///
/// # Errors
///
/// Returns a value-free operating-system error when the descriptor is not a
/// freezable map, the map was already frozen, or the caller lacks BPF
/// authority.
#[cfg(target_os = "linux")]
pub fn freeze_bpf_map(map: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    platform::freeze_bpf_map(map)
}

/// Prove that one exact BPF map is frozen against syscall-side mutation.
///
/// Linux does not expose the frozen bit in `bpf_map_info`, but does expose the
/// immutable `frozen` field for a live map descriptor in proc fdinfo. This
/// helper performs a bounded, exact parse and requires the value to be one.
///
/// # Errors
///
/// Returns a value-free error when proc fdinfo is unavailable, malformed,
/// over-bound, ambiguous, or reports an unfrozen object.
#[cfg(target_os = "linux")]
pub fn verify_bpf_map_frozen(map: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    platform::verify_bpf_map_frozen(map)
        .map_err(|error| io::Error::new(error.kind(), "bpf_map_frozen"))
}

/// Open and validate one pinned XDP BPF link as a retained exact descriptor.
///
/// `path` must be absolute and must not contain a NUL byte.
pub fn open_xdp_link_from_pin(path: &Path) -> io::Result<BpfXdpLink> {
    validate_xdp_link_pin_path(path)?;
    platform::open_xdp_link_from_pin(path).map(|inner| BpfXdpLink { inner })
}

/// Open and validate one XDP BPF link by kernel object ID as a retained exact
/// descriptor.
///
/// Linux gates this operation on effective `CAP_SYS_ADMIN`.
pub fn open_xdp_link_by_id(link_id: u32) -> io::Result<BpfXdpLink> {
    validate_xdp_link_id(link_id)?;
    platform::open_xdp_link_by_id(link_id).map(|inner| BpfXdpLink { inner })
}

fn validate_xdp_link_pin_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BPF link pin path must be absolute",
        ));
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BPF link pin path contains NUL",
        ));
    }
    Ok(())
}

fn validate_xdp_link_id(link_id: u32) -> io::Result<()> {
    if link_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "BPF link id must be non-zero",
        ));
    }
    Ok(())
}

/// Open and validate one XDP program by kernel object ID as a retained exact
/// descriptor.
///
/// Linux gates this operation on effective `CAP_SYS_ADMIN`.
pub fn open_xdp_program_by_id(program_id: u32) -> io::Result<BpfXdpProgram> {
    platform::open_xdp_program_by_id(program_id).map(|inner| BpfXdpProgram { inner })
}

/// Send one raw netlink message buffer to the kernel.
pub fn send_message(socket: &NetlinkSocket, payload: &[u8]) -> io::Result<usize> {
    platform::send_message(&socket.inner, payload)
}

/// Receive one raw netlink message buffer from the kernel.
///
/// # Datagram sizing
///
/// Netlink is a datagram protocol. If `buffer` is smaller than the kernel's
/// pending datagram, the kernel would silently drop the excess bytes when
/// `recv` is called with `flags=0`. To avoid silent truncation, this wrapper
/// passes `MSG_TRUNC` and returns an [`io::Error`] of kind
/// [`io::ErrorKind::InvalidData`] if the real datagram length exceeds
/// `buffer.len()`.
pub fn receive_message(socket: &NetlinkSocket, buffer: &mut [u8]) -> io::Result<usize> {
    platform::receive_message(&socket.inner, buffer)
}

/// Receive one raw unicast netlink datagram and authenticate its kernel sender.
///
/// Unlike [`receive_message`], this boundary retains and validates the source
/// `sockaddr_nl`. It rejects user-space peers even if their payload forges the
/// expected netlink sequence and port-id fields. Authoritative ACK, echo, and
/// dump consumers should use this function.
///
/// The same truncation guarantee as [`receive_message`] applies.
pub fn receive_kernel_message(socket: &NetlinkSocket, buffer: &mut [u8]) -> io::Result<usize> {
    platform::receive_kernel_message(&socket.inner, buffer)
}

/// Netlink request flag.
pub const NLM_F_REQUEST: u16 = 0x0001;
/// Netlink multipart response flag.
pub const NLM_F_MULTI: u16 = 0x0002;
/// Netlink acknowledge request flag.
pub const NLM_F_ACK: u16 = 0x0004;
/// Netlink echo request flag.
pub const NLM_F_ECHO: u16 = 0x0008;
/// Netlink dump was interrupted and its result is inconsistent.
pub const NLM_F_DUMP_INTR: u16 = 0x0010;
/// Netlink root dump flag.
pub const NLM_F_ROOT: u16 = 0x0100;
/// Netlink match dump flag.
pub const NLM_F_MATCH: u16 = 0x0200;
/// Netlink atomic dump flag.
pub const NLM_F_ATOMIC: u16 = 0x0400;
/// Netlink dump flag combination.
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
/// Netlink replacement flag for create/update operations.
pub const NLM_F_REPLACE: u16 = 0x0100;
/// Netlink exclusive-create flag.
pub const NLM_F_EXCL: u16 = 0x0200;
/// Netlink create flag.
pub const NLM_F_CREATE: u16 = 0x0400;
/// Netlink append flag.
pub const NLM_F_APPEND: u16 = 0x0800;

/// Netlink no-op control message.
pub const NLMSG_NOOP: u16 = 0x1;
/// Netlink error or acknowledge control message.
pub const NLMSG_ERROR: u16 = 0x2;
/// Netlink multipart completion control message.
pub const NLMSG_DONE: u16 = 0x3;
/// Netlink overrun control message.
pub const NLMSG_OVERRUN: u16 = 0x4;

/// Create a network link.
pub const RTM_NEWLINK: u16 = 16;
/// Delete a network link.
pub const RTM_DELLINK: u16 = 17;
/// Query a network link.
pub const RTM_GETLINK: u16 = 18;

/// Create a traffic-control filter.
pub const RTM_NEWTFILTER: u16 = 44;
/// Delete a traffic-control filter.
pub const RTM_DELTFILTER: u16 = 45;
/// Query traffic-control filters.
pub const RTM_GETTFILTER: u16 = 46;

/// Traffic-control attribute: classifier kind string.
pub const TCA_KIND: u16 = 1;
/// Traffic-control attribute: classifier-specific options nest.
pub const TCA_OPTIONS: u16 = 2;
/// cls_bpf attribute: attached BPF program name.
pub const TCA_BPF_NAME: u16 = 7;
/// cls_bpf attribute: attached BPF program identifier.
pub const TCA_BPF_ID: u16 = 11;

/// tc parent handle for the clsact ingress hook.
pub const TC_H_CLSACT_INGRESS: u32 = 0xFFFF_FFF2;
/// tc parent handle for the clsact egress hook.
pub const TC_H_CLSACT_EGRESS: u32 = 0xFFFF_FFF3;

/// Linux address family unspecified.
pub const AF_UNSPEC: u8 = 0;
/// Linux IPv4 address family.
pub const AF_INET: u8 = 2;
/// Linux IPv6 address family.
pub const AF_INET6: u8 = 10;

/// Interface is administratively up.
pub const IFF_UP: u32 = 0x1;

/// Link attribute: interface name.
pub const IFLA_IFNAME: u16 = 3;
/// Link attribute: interface alias.
pub const IFLA_IFALIAS: u16 = 20;
/// Link attribute: link information nest.
pub const IFLA_LINKINFO: u16 = 18;
/// Link-info attribute: device kind string.
pub const IFLA_INFO_KIND: u16 = 1;
/// Link-info attribute: device-kind-specific data nest.
pub const IFLA_INFO_DATA: u16 = 2;

/// GTP link-info attribute: GTPv0 socket fd.
pub const IFLA_GTP_FD0: u16 = 1;
/// GTP link-info attribute: GTPv1-U socket fd.
pub const IFLA_GTP_FD1: u16 = 2;
/// GTP link-info attribute: PDP hash size.
pub const IFLA_GTP_PDP_HASHSIZE: u16 = 3;
/// GTP link-info attribute: SGSN/GGSN role.
pub const IFLA_GTP_ROLE: u16 = 4;
/// GTP link-info attribute: kernel creates sockets.
pub const IFLA_GTP_CREATE_SOCKETS: u16 = 5;
/// GTP link-info attribute: restart counter.
pub const IFLA_GTP_RESTART_COUNT: u16 = 6;
/// GTP link-info attribute: local IPv4 address.
pub const IFLA_GTP_LOCAL: u16 = 7;
/// GTP link-info attribute: local IPv6 address.
pub const IFLA_GTP_LOCAL6: u16 = 8;

/// Linux GTP role for GGSN/P-GW-side tunnel endpoint behavior.
pub const GTP_ROLE_GGSN: u32 = 0;
/// Linux GTP role for SGSN-side tunnel endpoint behavior.
pub const GTP_ROLE_SGSN: u32 = 1;

/// Generic netlink control family id.
pub const GENL_ID_CTRL: u16 = 0x10;
/// Generic netlink control command: get family by name/id.
pub const CTRL_CMD_GETFAMILY: u8 = 3;
/// Generic netlink control family version.
pub const CTRL_VERSION: u8 = 1;
/// Generic netlink control attr: family id.
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
/// Generic netlink control attr: family name.
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;

/// Linux GTP generic-netlink family name.
pub const GTP_GENL_NAME: &str = "gtp";
/// Linux GTP generic-netlink family version used by libgtpnl.
pub const GTP_GENL_VERSION: u8 = 0;
/// GTP generic-netlink command: create PDP context.
pub const GTP_CMD_NEWPDP: u8 = 0;
/// GTP generic-netlink command: delete PDP context.
pub const GTP_CMD_DELPDP: u8 = 1;
/// GTP generic-netlink command: get PDP context.
pub const GTP_CMD_GETPDP: u8 = 2;
/// GTP generic-netlink command: echo request.
pub const GTP_CMD_ECHOREQ: u8 = 3;

/// GTP version 0.
pub const GTP_V0: u32 = 0;
/// GTP version 1.
pub const GTP_V1: u32 = 1;

/// GTP PDP attribute: link ifindex.
pub const GTPA_LINK: u16 = 1;
/// GTP PDP attribute: GTP version.
pub const GTPA_VERSION: u16 = 2;
/// GTP PDP attribute: GTPv0 tunnel id.
pub const GTPA_TID: u16 = 3;
/// GTP PDP attribute: IPv4 peer address.
pub const GTPA_PEER_ADDRESS: u16 = 4;
/// GTP PDP attribute: IPv4 MS/UE address.
pub const GTPA_MS_ADDRESS: u16 = 5;
/// GTP PDP attribute: GTPv0 flow id.
pub const GTPA_FLOW: u16 = 6;
/// GTP PDP attribute: target netns fd.
pub const GTPA_NET_NS_FD: u16 = 7;
/// GTP PDP attribute: incoming/local GTPv1 TEID.
pub const GTPA_I_TEI: u16 = 8;
/// GTP PDP attribute: outgoing/peer GTPv1 TEID.
pub const GTPA_O_TEI: u16 = 9;
/// GTP PDP attribute: padding.
pub const GTPA_PAD: u16 = 10;
/// GTP PDP attribute: IPv6 peer address.
pub const GTPA_PEER_ADDR6: u16 = 11;
/// GTP PDP attribute: IPv6 MS/UE address.
pub const GTPA_MS_ADDR6: u16 = 12;
/// GTP PDP attribute: MS/UE address family.
pub const GTPA_FAMILY: u16 = 13;

/// Netlink message header layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NetlinkMessageHeader {
    /// Total message length including this header.
    pub length: u32,
    /// Message type.
    pub message_type: u16,
    /// Netlink flags.
    pub flags: u16,
    /// Caller-supplied sequence number.
    pub sequence: u32,
    /// Netlink port identifier.
    pub port_id: u32,
}

/// Netlink route/generic attribute header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RouteAttributeHeader {
    /// Attribute length including this header.
    pub length: u16,
    /// Attribute type.
    pub attr_type: u16,
}

/// Linux `struct ifinfomsg` used by rtnetlink link operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct IfInfoMessage {
    /// Address family.
    pub family: u8,
    /// Padding byte.
    pub pad: u8,
    /// Device type.
    pub device_type: u16,
    /// Interface index.
    pub index: i32,
    /// Interface flags.
    pub flags: u32,
    /// Interface change mask.
    pub change: u32,
}

/// Linux `struct genlmsghdr` used by generic netlink messages.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct GenericNetlinkHeader {
    /// Generic netlink command.
    pub command: u8,
    /// Generic netlink family version.
    pub version: u8,
    /// Reserved field.
    pub reserved: u16,
}

/// Linux `struct nlmsgerr` prefix used by netlink ACK/error responses.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NetlinkErrorMessage {
    /// Negative errno on failure, or zero for success.
    pub error: i32,
    /// Header of the request being acknowledged.
    pub message: NetlinkMessageHeader,
}

/// Align a netlink message or route attribute length to the Linux 4-byte boundary.
#[must_use]
pub const fn align_to_netlink(value: usize) -> Option<usize> {
    match value.checked_add(3) {
        Some(padded) => Some(padded & !3),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[cfg(target_os = "linux")]
    use std::ffi::OsString;
    #[cfg(target_os = "linux")]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(target_os = "linux")]
    use std::path::PathBuf;

    #[test]
    fn constants_cover_gtpu_rtnl_and_genl_values() {
        assert_eq!(NETLINK_ROUTE, 0);
        assert_eq!(NETLINK_GENERIC, 16);
        assert_eq!(NLM_F_REQUEST, 0x0001);
        assert_eq!(NLM_F_ACK, 0x0004);
        assert_eq!(NLM_F_DUMP_INTR, 0x0010);
        assert_eq!(NLM_F_DUMP, 0x0300);
        assert_eq!(NLM_F_EXCL, 0x0200);
        assert_eq!(NLM_F_CREATE, 0x0400);
        assert_eq!(NLMSG_ERROR, 0x2);
        assert_eq!(NLMSG_DONE, 0x3);
        assert_eq!(RTM_NEWLINK, 16);
        assert_eq!(RTM_DELLINK, 17);
        assert_eq!(RTM_NEWTFILTER, 44);
        assert_eq!(RTM_DELTFILTER, 45);
        assert_eq!(RTM_GETTFILTER, 46);
        assert_eq!(TCA_KIND, 1);
        assert_eq!(TCA_OPTIONS, 2);
        assert_eq!(TCA_BPF_NAME, 7);
        assert_eq!(TCA_BPF_ID, 11);
        assert_eq!(TC_H_CLSACT_INGRESS, 0xFFFF_FFF2);
        assert_eq!(TC_H_CLSACT_EGRESS, 0xFFFF_FFF3);
        assert_eq!(AF_UNSPEC, 0);
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(IFLA_IFNAME, 3);
        assert_eq!(IFLA_IFALIAS, 20);
        assert_eq!(IFLA_LINKINFO, 18);
        assert_eq!(IFLA_INFO_KIND, 1);
        assert_eq!(IFLA_INFO_DATA, 2);
        assert_eq!(IFLA_GTP_FD0, 1);
        assert_eq!(IFLA_GTP_FD1, 2);
        assert_eq!(IFLA_GTP_PDP_HASHSIZE, 3);
        assert_eq!(IFLA_GTP_ROLE, 4);
        assert_eq!(IFLA_GTP_CREATE_SOCKETS, 5);
        assert_eq!(IFLA_GTP_RESTART_COUNT, 6);
        assert_eq!(IFLA_GTP_LOCAL, 7);
        assert_eq!(IFLA_GTP_LOCAL6, 8);
        assert_eq!(GTP_ROLE_GGSN, 0);
        assert_eq!(GTP_ROLE_SGSN, 1);
        assert_eq!(GENL_ID_CTRL, 0x10);
        assert_eq!(CTRL_CMD_GETFAMILY, 3);
        assert_eq!(CTRL_ATTR_FAMILY_ID, 1);
        assert_eq!(CTRL_ATTR_FAMILY_NAME, 2);
        assert_eq!(GTP_GENL_NAME, "gtp");
        assert_eq!(GTP_CMD_NEWPDP, 0);
        assert_eq!(GTP_CMD_DELPDP, 1);
        assert_eq!(GTP_CMD_GETPDP, 2);
        assert_eq!(GTP_V0, 0);
        assert_eq!(GTP_V1, 1);
        assert_eq!(GTPA_LINK, 1);
        assert_eq!(GTPA_VERSION, 2);
        assert_eq!(GTPA_PEER_ADDRESS, 4);
        assert_eq!(GTPA_MS_ADDRESS, 5);
        assert_eq!(GTPA_I_TEI, 8);
        assert_eq!(GTPA_O_TEI, 9);
        assert_eq!(GTPA_PEER_ADDR6, 11);
        assert_eq!(GTPA_MS_ADDR6, 12);
        assert_eq!(GTPA_FAMILY, 13);
    }

    #[test]
    fn cgroup_program_query_debug_is_value_free() {
        let query = BpfCgroupProgramQuery {
            attach_flags: 2,
            revision: 29,
            attachments: vec![
                BpfCgroupProgramAttachment {
                    program_id: 17,
                    program_attach_flags: 31,
                },
                BpfCgroupProgramAttachment {
                    program_id: 23,
                    program_attach_flags: 43,
                },
            ],
        };

        let debug = format!("{query:?}");
        assert!(debug.contains("program_count: 2"));
        assert!(!debug.contains("17"));
        assert!(!debug.contains("23"));
        assert!(!debug.contains("29"));
        assert!(!debug.contains("31"));
        assert!(!debug.contains("37"));
        assert!(!debug.contains("41"));
        assert!(!debug.contains("43"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bpf_link_open_rejects_invalid_inputs_before_any_syscall() {
        let error = open_xdp_link_by_id(0).expect_err("zero link id");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let error =
            open_xdp_link_from_pin(Path::new("relative/link")).expect_err("relative pin path");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let nul_path = PathBuf::from(OsString::from_vec(b"/sys/fs/bpf/bad\0link".to_vec()));
        let error = open_xdp_link_from_pin(&nul_path).expect_err("NUL pin path");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn netlink_alignment_is_checked() {
        assert_eq!(align_to_netlink(0), Some(0));
        assert_eq!(align_to_netlink(1), Some(4));
        assert_eq!(align_to_netlink(4), Some(4));
        assert_eq!(align_to_netlink(5), Some(8));
        assert_eq!(align_to_netlink(usize::MAX), None);
    }

    #[test]
    fn uapi_layout_matches_linux_headers() {
        assert_eq!(size_of::<NetlinkMessageHeader>(), 16);
        assert_eq!(align_of::<NetlinkMessageHeader>(), 4);
        assert_eq!(size_of::<RouteAttributeHeader>(), 4);
        assert_eq!(size_of::<IfInfoMessage>(), 16);
        assert_eq!(offset_of!(IfInfoMessage, index), 4);
        assert_eq!(offset_of!(IfInfoMessage, flags), 8);
        assert_eq!(offset_of!(IfInfoMessage, change), 12);
        assert_eq!(size_of::<GenericNetlinkHeader>(), 4);
        assert_eq!(size_of::<NetlinkErrorMessage>(), 20);
        assert_eq!(offset_of!(NetlinkErrorMessage, message), 4);
    }
}

#[cfg(all(test, target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
mod udp_socket_borrow_tests {
    use super::{open_gtpu_udp_socket, GtpuIpAddress, GtpuUdpBind};
    use std::os::fd::AsRawFd;

    /// The GTP netdevice takes its own reference from the fd *number*, so the
    /// owning handle stays with this crate. A borrow lets a caller read the
    /// socket's receive queue -- where the kernel passes up every non-G-PDU
    /// message -- without reconstructing ownership it was never given, and
    /// without needing `unsafe` in a crate that forbids it.
    #[test]
    fn borrowed_fd_matches_the_number_handed_to_the_kernel() {
        let socket = match open_gtpu_udp_socket(GtpuUdpBind {
            address: GtpuIpAddress::Ipv4([127, 0, 0, 1]),
            port: 0,
        }) {
            Ok(socket) => socket,
            // Sandboxes without permission to bind are not a failure of this
            // property. Note that libtest captures stderr from a passing test,
            // so this marker is only visible under `--nocapture`; the run is
            // green either way.
            Err(error) => {
                eprintln!("skipping: cannot bind a local GTP-U UDP socket: {error}");
                return;
            }
        };

        assert_eq!(
            socket.as_fd().as_raw_fd(),
            socket.raw_fd(),
            "the borrow must name the same descriptor passed as IFLA_GTP_FD1"
        );
        // Borrowing must not close or move the descriptor.
        assert_eq!(socket.as_fd().as_raw_fd(), socket.raw_fd());
        assert!(socket.raw_fd() >= 0);
    }
}

#[cfg(all(test, target_os = "linux", not(opc_linux_gtpu_sys_force_unsupported)))]
mod socket_kernel_identity_tests {
    use std::{os::fd::AsFd, os::unix::net::UnixDatagram};

    use super::socket_kernel_identity;

    #[test]
    fn exact_socket_cookies_are_nonzero_and_redacted() {
        let (left, right) = UnixDatagram::pair().expect("fixture socket pair");
        let left = socket_kernel_identity(left.as_fd()).expect("left identity");
        let right = socket_kernel_identity(right.as_fd()).expect("right identity");

        assert_ne!(left.socket_cookie(), 0);
        assert_ne!(right.socket_cookie(), 0);
        assert_ne!(left.socket_cookie(), right.socket_cookie());
        assert_eq!(format!("{left:?}"), "SocketKernelIdentity(<redacted>)");
    }
}
