//! Lease-bound kernel egress fencing for datagram sockets.
//!
//! A Linux root-cgroup eBPF gate authorizes datagrams only while the exact
//! socket cookie is bound to a live durable store lease. The userspace lifecycle
//! captures suspend-aware time before each lease operation, derives a
//! conservative kernel deadline from that start, and terminal-closes on every
//! failure or cancellation path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod guardian;
#[cfg(target_os = "linux")]
mod install_manifest;
mod lifecycle;
#[cfg(target_os = "linux")]
mod linux_backend;
#[cfg(target_os = "linux")]
mod linux_control;
#[cfg(target_os = "linux")]
mod pin_store;
#[cfg(target_os = "linux")]
mod root_cgroup;
#[cfg(target_os = "linux")]
mod root_inventory;
mod socket;

pub use guardian::{
    fenced_udp_channels, run_fenced_udp_guardian, FencedUdpChannelError, FencedUdpChannels,
    FencedUdpGuardianError, FencedUdpGuardianPorts, FencedUdpInboundDatagram, FencedUdpSender,
    GuardianOperationalError,
};
pub use lifecycle::{
    DurablePriorFenceState, EgressFenceLeaseAuthority, FenceAttachmentIdentity, FenceError,
    FenceLeaseGrant, LeaseFenceError, LeaseFenceTiming, TerminalClosureEvidence,
};
#[cfg(target_os = "linux")]
pub use linux_backend::{
    install_or_adopt_linux_egress_fence, LinuxEgressFenceConfig, LinuxEgressFenceError,
    LinuxEgressFenceSocket,
};
#[cfg(target_os = "linux")]
pub use root_cgroup::HostCgroupV2Root;
pub use socket::{FencedUdpSocket, RetireFenceError};

#[cfg(test)]
mod lifecycle_tests;
